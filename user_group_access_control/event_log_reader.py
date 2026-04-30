"""
EventLogReader: Polls the Windows Security Event Log for Event ID 4663 entries,
applies noise filters, maps AccessMask to Operation, and emits AccessEvent records.
"""

import os
import re
import sys
import threading
import time
from datetime import datetime
from typing import Callable

from user_group_access_control.models import AccessEvent, Operation

# Guard pywin32 import — not available on non-Windows or without pywin32 installed
try:
    import win32evtlog
    import win32evtlogutil
    _WIN32_AVAILABLE = True
except ImportError:
    _WIN32_AVAILABLE = False

# System account names to discard (case-insensitive)
_SYSTEM_ACCOUNT_NAMES = {"system", "local service", "network service"}

# Prefixes for session-manager accounts to discard (case-insensitive)
_SYSTEM_ACCOUNT_PREFIXES = ("dwm-", "umfd-")

# Process names to ignore (case-insensitive) - background Windows processes
_IGNORED_PROCESSES = {
    "searchindexer.exe",  # Windows Search Indexer
    "searchprotocolhost.exe",  # Windows Search Protocol Host
    "msmpeng.exe",  # Windows Defender
    "mssense.exe",  # Windows Defender Advanced Threat Protection
    "onedrive.exe",  # OneDrive sync
    "vssvc.exe",  # Volume Shadow Copy
    "trustedinstaller.exe",  # Windows Module Installer
}

# Default polling interval in seconds
_DEFAULT_INTERVAL = 0.1  # Poll every 100ms for near-instant detection


def _map_access_mask(mask: int) -> list[Operation]:
    """
    Map an integer AccessMask to all applicable Operations.

    Collects all operations indicated by the access mask bits instead of
    returning only the highest-priority operation. This allows capturing
    multiple operations that occur in a single event (e.g., READ + WRITE
    when a file is opened for editing).

    Returns a list of all operations found, or an empty list if no relevant
    bits are set.
    
    Windows File Access Rights:
    - 0x1 = FILE_READ_DATA / FILE_LIST_DIRECTORY
    - 0x2 = FILE_WRITE_DATA / FILE_ADD_FILE
    - 0x4 = FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    - 0x20 = FILE_EXECUTE / FILE_TRAVERSE
    - 0x40 = FILE_DELETE_CHILD
    - 0x80 = FILE_READ_ATTRIBUTES
    - 0x100 = FILE_WRITE_ATTRIBUTES
    - 0x10000 = DELETE
    """
    operations = []
    
    # DELETE: 0x10000 (DELETE) or 0x40 (DeleteChild)
    if mask & 0x10000 or mask & 0x40:
        operations.append("DELETE")
    
    # WRITE: 0x2 (WriteData/AddFile) or 0x100 (WriteAttributes)
    # Note: 0x4 (AppendData) is for CREATE, not WRITE
    if mask & 0x2 or mask & 0x100:
        operations.append("WRITE")
    
    # CREATE: 0x4 (AppendData/AddSubdirectory)
    # This is the bit set when creating new files/folders
    if mask & 0x4:
        operations.append("CREATE")
    
    # READ: 0x1 (ListDirectory/ReadData) or 0x20 (Traverse/Execute)
    if mask & 0x1 or mask & 0x20:
        operations.append("READ")
    
    return operations


def _is_system_account(username: str) -> bool:
    """
    Return True if the username belongs to a system/noise account that should be filtered.

    Filters:
    - Ends with '$' (machine accounts)
    - Is SYSTEM, LOCAL SERVICE, or NETWORK SERVICE (case-insensitive)
    - Starts with DWM- or UMFD- (case-insensitive)
    """
    if username.endswith("$"):
        return True
    lower = username.lower()
    if lower in _SYSTEM_ACCOUNT_NAMES:
        return True
    for prefix in _SYSTEM_ACCOUNT_PREFIXES:
        if lower.startswith(prefix):
            return True
    return False


class EventLogReader:
    """
    Continuously polls the Windows Security Event Log for Event ID 4663 entries
    on watched paths and converts them into AccessEvent records.
    """

    def __init__(self, interval: float = _DEFAULT_INTERVAL) -> None:
        self._interval = interval
        self._watched_paths: list[str] = []
        self._event_handler: "Callable[[AccessEvent], None] | None" = None
        self._stop_event = threading.Event()
        self._thread: "threading.Thread | None" = None
        self._last_record_number: int = 0
        self._log_file_path: str = ""
        self._state_file: str = "event_reader_state.txt"
        
        # Event correlation state for RENAME detection
        # Maps path -> (timestamp, username) for recent DELETE events
        self._recent_deletes: dict[str, tuple[datetime, str]] = {}
        # Maps folder_path -> timestamp for recent folder access
        self._recent_folder_opens: dict[str, datetime] = {}
        # Correlation time window in seconds (100ms)
        self._correlation_window: float = 0.1

    def _load_last_record_number(self) -> None:
        """Load the last processed record number from disk."""
        try:
            if os.path.exists(self._state_file):
                with open(self._state_file, 'r') as f:
                    self._last_record_number = int(f.read().strip())
                print(f"[EventLogReader] Resuming from record #{self._last_record_number}")
            else:
                # First run: get the latest record number to skip all old events
                self._initialize_to_latest_record()
        except Exception as exc:
            print(f"[EventLogReader] Could not load state: {exc}", file=sys.stderr)
            self._last_record_number = 0

    def _initialize_to_latest_record(self) -> None:
        """On first run, set last_record_number to the most recent event to skip history."""
        if not _WIN32_AVAILABLE:
            return
        
        try:
            handle = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            # Read just the first (most recent) event
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if events:
                self._last_record_number = events[0].RecordNumber
                print(f"[EventLogReader] First run: starting from latest record #{self._last_record_number}")
            
            win32evtlog.CloseEventLog(handle)
        except Exception as exc:
            print(f"[EventLogReader] Could not initialize to latest record: {exc}", file=sys.stderr)

    def _save_last_record_number(self) -> None:
        """Save the last processed record number to disk."""
        try:
            with open(self._state_file, 'w') as f:
                f.write(str(self._last_record_number))
        except Exception as exc:
            print(f"[EventLogReader] Could not save state: {exc}", file=sys.stderr)

    def set_log_file_path(self, path: str) -> None:
        """
        Tell the reader which file is the system log file so it can filter
        out events generated by the logging layer itself.
        """
        self._log_file_path = path

    def start_polling(
        self,
        watched_paths: list[str],
        event_handler: "Callable[[AccessEvent], None]",
    ) -> None:
        """
        Begin polling the Security Event Log on a background daemon thread.

        Args:
            watched_paths: List of absolute Windows paths to monitor.
            event_handler: Callback invoked for each AccessEvent that passes
                           all noise filters.
        """
        self._watched_paths = watched_paths
        self._event_handler = event_handler
        self._stop_event.clear()

        # Load the last record number to avoid reprocessing old events
        self._load_last_record_number()

        self._thread = threading.Thread(target=self._polling_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the polling thread to stop and wait for it to finish (up to 5 s)."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        
        # Emit any remaining orphaned DELETEs before stopping
        # These are likely folder deletions (Event ID 4659 doesn't capture folder deletions)
        if self._event_handler is not None:
            for deleted_path, (delete_time, delete_user) in self._recent_deletes.items():
                self._event_handler(AccessEvent(
                    username=delete_user,
                    path=deleted_path,
                    operation="DELETE",
                    timestamp=delete_time,
                ))
            self._recent_deletes.clear()
        
        # Save state before exiting
        self._save_last_record_number()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _cleanup_stale_correlation_entries(self, current_time: datetime) -> None:
        """
        Remove entries from correlation state that are older than the correlation window.
        This prevents unbounded memory growth.
        """
        cutoff_time = current_time.timestamp() - self._correlation_window
        
        # Clean up old DELETE events
        stale_deletes = [
            path for path, (timestamp, _) in self._recent_deletes.items()
            if timestamp.timestamp() < cutoff_time
        ]
        for path in stale_deletes:
            del self._recent_deletes[path]
        
        # Clean up old folder open events
        stale_opens = [
            path for path, timestamp in self._recent_folder_opens.items()
            if timestamp.timestamp() < cutoff_time
        ]
        for path in stale_opens:
            del self._recent_folder_opens[path]

    def _polling_loop(self) -> None:
        """Main loop: sleep, then poll, until the stop event is set."""
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self._interval)
            if not self._stop_event.is_set():
                self._poll_once()

    def _poll_once(self) -> None:
        """
        Read new Security Event Log entries since _last_record_number,
        apply noise filters, map AccessMask to Operations, and call the
        event handler for each surviving AccessEvent.
        
        Now handles multiple AccessEvents per raw event (e.g., READ + WRITE
        for file edits).
        """
        if not _WIN32_AVAILABLE:
            return

        try:
            handle = win32evtlog.OpenEventLog(None, "Security")
        except Exception as exc:
            print(f"[EventLogReader] Failed to open Security event log: {exc}", file=sys.stderr)
            return

        try:
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            max_record_seen = self._last_record_number

            while True:
                try:
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                except Exception as exc:
                    print(f"[EventLogReader] ReadEventLog error: {exc}", file=sys.stderr)
                    break

                if not events:
                    break

                for event in events:
                    record_number = event.RecordNumber

                    # Skip already-processed events
                    if record_number <= self._last_record_number:
                        continue

                    if record_number > max_record_seen:
                        max_record_seen = record_number

                    # Process Event ID 4663 (file access) and Event ID 4659 (deletion intent).
                    # win32evtlog on Python 3 sometimes returns the EventID
                    # with the high 16 bits set (e.g. 0x80001237 instead of
                    # 0x1237 = 4663), so mask off the high bits before comparing.
                    event_id = event.EventID & 0xFFFF
                    if event_id not in (4663, 4659):
                        continue

                    # Process event and get list of AccessEvents (may be empty, or contain multiple events)
                    access_events = self._process_event(event, event_id)
                    
                    # Emit each AccessEvent to the handler
                    if self._event_handler is not None:
                        for access_event in access_events:
                            self._event_handler(access_event)

            self._last_record_number = max_record_seen
            # Periodically save state
            self._save_last_record_number()

        finally:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass

    def _process_event(self, event: object, event_id: int) -> "list[AccessEvent]":
        """
        Dispatcher that routes events to the appropriate handler based on event ID.
        
        Args:
            event: Raw win32evtlog event object
            event_id: Event ID (4663 or 4659)
        
        Returns:
            List of AccessEvents (may be empty if filtered)
        """
        if event_id == 4663:
            return self._process_4663_event(event)
        elif event_id == 4659:
            return self._process_4659_event(event)
        else:
            return []
    
    def _process_4659_event(self, event: object) -> "list[AccessEvent]":
        """
        Process Event ID 4659 - "A handle to an object was requested with intent to delete".
        This event captures actual file/folder deletions.
        
        Args:
            event: Raw win32evtlog event object
        
        Returns:
            List containing a single DELETE AccessEvent, or empty list if filtered
        """
        inserts = getattr(event, "StringInserts", None)
        if not inserts or len(inserts) < 7:
            return []
        
        subject_user_name: str = inserts[1] or ""
        object_name: str = inserts[6] or ""
        
        # --- Noise filter 1: machine accounts and system accounts ---
        if _is_system_account(subject_user_name):
            return []
        
        # --- Noise filter 2: discard events for the system log file ---
        if self._log_file_path:
            if os.path.normcase(object_name) == os.path.normcase(self._log_file_path):
                return []
        
        # --- Noise filter 3: ObjectName must match or be inside a watched path ---
        norm_object = os.path.normcase(object_name)
        watched = False
        for wp in self._watched_paths:
            norm_wp = os.path.normcase(wp)
            
            # Check if it's inside the watched path (file or subfolder)
            if norm_object.startswith(norm_wp + os.sep):
                watched = True
                break
            
            # Check if it's exactly the watched path itself
            elif norm_object == norm_wp:
                watched = True
                break
        
        if not watched:
            return []
        
        # --- Extract timestamp ---
        time_generated = getattr(event, "TimeGenerated", None)
        if time_generated is None:
            timestamp = datetime.now()
        else:
            # win32evtlog returns TimeGenerated as a pytime object; convert to datetime
            # For mock objects in tests, TimeGenerated might already be a datetime
            if isinstance(time_generated, datetime):
                timestamp = time_generated
            else:
                try:
                    timestamp = datetime(
                        time_generated.year,
                        time_generated.month,
                        time_generated.day,
                        time_generated.hour,
                        time_generated.minute,
                        time_generated.second,
                        time_generated.microsecond if hasattr(time_generated, 'microsecond') else 0,
                    )
                except Exception:
                    timestamp = datetime.now()
        
        # Event ID 4659 indicates actual deletion - emit DELETE immediately
        return [AccessEvent(
            username=subject_user_name,
            path=object_name,
            operation="DELETE",
            timestamp=timestamp,
        )]
    
    def _process_4663_event(self, event: object) -> "list[AccessEvent]":
        """
        Extract fields from a raw win32evtlog Event ID 4663 event, apply noise filters,
        map the AccessMask, and return a list of AccessEvents (one per operation) — 
        or empty list if filtered.
        """
        inserts = getattr(event, "StringInserts", None)
        if not inserts or len(inserts) < 10:
            return []

        subject_user_name: str = inserts[1] or ""
        object_type: str = inserts[5] or ""
        object_name: str = inserts[6] or ""
        access_mask_str: str = inserts[9] or ""

        # --- Noise filter 1: machine accounts (end with '$') and system accounts ---
        if _is_system_account(subject_user_name):
            return []

        # --- Noise filter 2: ObjectType must be 'File' ---
        if object_type != "File":
            return []

        # --- Noise filter 3: parse AccessMask ---
        try:
            mask = int(access_mask_str, 16)
        except (ValueError, TypeError):
            return []

        # --- Noise filter 4: discard ReadAttributes-only events (0x80) ---
        if mask == 0x80:
            return []

        # --- Noise filter 5: discard events for the system log file ---
        if self._log_file_path:
            if os.path.normcase(object_name) == os.path.normcase(self._log_file_path):
                return []

        # --- Noise filter 6: ObjectName must match or be inside a watched path ---
        # Match both:
        # 1. Files/folders inside the watched folder (all operations)
        # 2. The watched folder itself (when entering or modifying it)
        norm_object = os.path.normcase(object_name)
        watched = False
        for wp in self._watched_paths:
            norm_wp = os.path.normcase(wp)
            
            # Check if it's inside the watched path (file or subfolder)
            if norm_object.startswith(norm_wp + os.sep):
                watched = True
                break
            
            # Check if it's exactly the watched path itself
            elif norm_object == norm_wp:
                # For the folder itself, we want to catch when user enters it
                # Skip ONLY if it's ReadAttributes-only (0x80) - already filtered above
                # All other operations (including Traverse, ReadData, etc.) should trigger
                watched = True
                break
                
        if not watched:
            return []

        # --- Map AccessMask to Operations ---
        operations = _map_access_mask(mask)
        if not operations:
            return []

        # --- Extract timestamp ---
        time_generated = getattr(event, "TimeGenerated", None)
        if time_generated is None:
            timestamp = datetime.now()
        else:
            # win32evtlog returns TimeGenerated as a pytime object; convert to datetime
            # For mock objects in tests, TimeGenerated might already be a datetime
            if isinstance(time_generated, datetime):
                timestamp = time_generated
            else:
                try:
                    timestamp = datetime(
                        time_generated.year,
                        time_generated.month,
                        time_generated.day,
                        time_generated.hour,
                        time_generated.minute,
                        time_generated.second,
                        time_generated.microsecond if hasattr(time_generated, 'microsecond') else 0,
                    )
                except Exception:
                    timestamp = datetime.now()

        # --- Event correlation for RENAME detection ---
        # Clean up stale entries periodically
        self._cleanup_stale_correlation_entries(timestamp)
        
        # --- Folder enumeration filtering ---
        # Check if this is a folder (we'll track it after processing if it's a READ)
        is_folder = os.path.isdir(object_name) if os.path.exists(object_name) else False
        has_read = mask & 0x1
        
        # Process each operation and apply correlation logic
        result_events: list[AccessEvent] = []
        
        # Track if we should record this folder as being opened (for enumeration filtering)
        should_track_folder_open = False
        
        for operation in operations:
            # --- Folder enumeration filtering for READ operations ---
            if operation == "READ":
                # Check if this is a folder/file whose parent was recently opened
                parent_folder = os.path.dirname(object_name)
                
                # If the parent folder was recently opened, this might be enumeration
                if parent_folder in self._recent_folder_opens:
                    parent_open_time = self._recent_folder_opens[parent_folder]
                    time_diff = (timestamp.timestamp() - parent_open_time.timestamp())
                    
                    # If parent was opened within correlation window, this is enumeration - suppress it
                    if 0 <= time_diff <= self._correlation_window:
                        # This is a child being enumerated as part of parent folder listing
                        continue  # Skip this READ operation (enumeration, not direct access)
                
                # Also suppress READ on the watched folder itself if it was just opened
                # (multiple READ events on same folder within short time = refresh/enumeration)
                if object_name in self._recent_folder_opens:
                    last_open_time = self._recent_folder_opens[object_name]
                    time_diff = (timestamp.timestamp() - last_open_time.timestamp())
                    
                    # If this folder was accessed very recently (within 2 seconds), suppress duplicate READ
                    if 0 < time_diff <= 2.0:  # 2 second window for duplicate suppression
                        continue
                
                # This is a legitimate READ - if it's a folder, we should track it
                if is_folder and has_read:
                    should_track_folder_open = True
                
                # No recent parent folder access - this is direct access, allow it to be logged
            
            # --- RENAME detection: Handle DELETE operations ---
            if operation == "DELETE":
                # Store the DELETE event - we'll check if a WRITE on parent folder follows
                # (Windows generates DELETE on old name + WRITE on parent for renames)
                self._recent_deletes[object_name] = (timestamp, subject_user_name)
                # Don't emit DELETE yet - wait to see if WRITE on parent follows
                continue
            
            # --- RENAME detection: Handle WRITE operations on folders ---
            if operation == "WRITE" and is_folder:
                # A WRITE on a folder might indicate a rename operation
                # Check if there's a recent DELETE of a child in this folder
                rename_detected = False
                for deleted_path, (delete_time, delete_user) in list(self._recent_deletes.items()):
                    deleted_parent = os.path.dirname(deleted_path)
                    
                    # Check if the DELETE was for a child of this folder
                    if os.path.normcase(deleted_parent) == os.path.normcase(object_name):
                        # Check if DELETE occurred within correlation window
                        time_diff = (timestamp.timestamp() - delete_time.timestamp())
                        if 0 <= time_diff <= self._correlation_window:
                            # This is a RENAME operation!
                            # Remove the DELETE from tracking
                            del self._recent_deletes[deleted_path]
                            
                            # Emit RENAME for the original (deleted) path
                            result_events.append(AccessEvent(
                                username=subject_user_name,
                                path=deleted_path,  # Use the original path
                                operation="RENAME",
                                timestamp=timestamp,
                            ))
                            rename_detected = True
                            break
                
                # If rename was detected, skip the WRITE operation (already emitted as RENAME)
                if rename_detected:
                    continue
                
                # No correlation found - this is a genuine WRITE on folder, fall through to emit it
            
            # Emit the operation as an AccessEvent
            result_events.append(AccessEvent(
                username=subject_user_name,
                path=object_name,
                operation=operation,
                timestamp=timestamp,
            ))
        
        # After processing all operations, track folder opens for enumeration filtering
        if should_track_folder_open:
            self._recent_folder_opens[object_name] = timestamp
        
        return result_events
