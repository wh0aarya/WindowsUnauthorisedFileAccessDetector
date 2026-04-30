"""
Logging Layer — appends structured unauthorized-access records to a text file.

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6
"""

import sys
import threading
from typing import Optional

from user_group_access_control.models import AccessEvent, Group


class LoggingLayer:
    """Appends one structured entry per unauthorized access event to a log file.

    Thread-safe: concurrent ``write_log`` calls are serialized via a
    ``threading.Lock`` so entries are never interleaved.
    """

    def __init__(self) -> None:
        self._log_file_path: Optional[str] = None
        self._lock: threading.Lock = threading.Lock()
        self._groups: list[Group] = []

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------

    def set_log_file(self, file_path: str) -> None:
        """Set (or change) the path of the log file.

        The file is created on the first ``write_log`` call if it does not
        already exist (opened in append mode).
        """
        self._log_file_path = file_path

    def set_groups(self, groups: list[Group]) -> None:
        """Provide the group list so that group display names can be resolved.

        If a ``group_id`` passed to ``write_log`` is not found in this list,
        the ``group_id`` itself is used as the display name.
        """
        self._groups = list(groups)

    # ------------------------------------------------------------------
    # Core write operation
    # ------------------------------------------------------------------

    def write_log(self, event: AccessEvent, group_id: str) -> None:
        """Append one structured entry for *event* to the configured log file.

        The entry format is::

            [YYYY-MM-DD HH:MM:SS] UNAUTHORIZED ACCESS
              User      : <username>
              Group     : <group_id> (<group_name>)
              Path      : <path>
              Operation : <operation>
              ----------------------------------------

        If the log file path has not been set, or if the file cannot be
        opened/written, an error is emitted to *stderr* and the method
        returns without raising.
        """
        if not self._log_file_path:
            print(
                "LoggingLayer: log file path is not set; cannot write log entry.",
                file=sys.stderr,
            )
            return

        group_name = self._resolve_group_name(group_id)
        entry = self._format_entry(event, group_id, group_name)

        with self._lock:
            try:
                with open(self._log_file_path, "a", encoding="utf-8") as fh:
                    fh.write(entry)
            except OSError as exc:
                print(
                    f"LoggingLayer: failed to write to log file "
                    f"'{self._log_file_path}': {exc}",
                    file=sys.stderr,
                )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_group_name(self, group_id: str) -> str:
        """Return the display name for *group_id*, or *group_id* if not found."""
        for group in self._groups:
            if group.id == group_id:
                return group.name
        return group_id

    @staticmethod
    def _format_entry(event: AccessEvent, group_id: str, group_name: str) -> str:
        """Build the formatted log entry string."""
        timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        return (
            f"[{timestamp}] UNAUTHORIZED ACCESS\n"
            f"  User      : {event.username}\n"
            f"  Group     : {group_id} ({group_name})\n"
            f"  Path      : {event.path}\n"
            f"  Operation : {event.operation}\n"
            f"  ----------------------------------------\n"
        )
