# User Group Access Control System

A Windows 11 file and folder access control system that monitors unauthorized access attempts in real-time using Windows Security Event Logs. The system classifies users into developer-defined groups, enforces per-group permissions, and provides immediate popup alerts with persistent audit logging.

## Overview

This system monitors file and folder access on Windows 11 by leveraging OS-level auditing (Event ID 4663 and 4659). When a user attempts to access a monitored path, the system evaluates the action against configured permissions and responds with:

- **Authorized access**: Silent (no action taken)
- **Unauthorized access**: Popup alert + persistent log entry

The system is designed as a prototype demo for a single Windows 11 user profile, demonstrating real-time security monitoring and access control enforcement.

## Key Features

- **Real-time monitoring** using Windows Security Event Logs (Event ID 4663 and 4659)
- **Group-based access control** with configurable permissions per group
- **Immediate popup alerts** for unauthorized access attempts
- **Persistent audit trail** in structured text format
- **Intelligent noise filtering** to exclude system processes and background operations
- **Folder enumeration filtering** to prevent false positives when browsing folders
- **Rename detection** using event correlation (distinguishes renames from deletions)
- **File deletion monitoring** via Event ID 4659
- **Event log position persistence** to avoid reprocessing old events on restart

## Architecture

The system consists of 8 core components:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Configuration Manager                        │
│              (Loads and validates config.json)                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│Policy Manager│    │User Manager  │    │Audit Policy  │
│              │    │              │    │Manager       │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                    │
       │                   │                    ▼
       │                   │            ┌──────────────┐
       │                   │            │Windows Event │
       │                   │            │Log (4663,    │
       │                   │            │     4659)    │
       │                   │            └──────┬───────┘
       │                   │                   │
       │                   │                   ▼
       │                   │            ┌──────────────┐
       │                   │            │Event Log     │
       │                   │            │Reader        │
       │                   │            └──────┬───────┘
       │                   │                   │
       │                   └───────┬───────────┘
       │                           │
       │                           ▼
       │                   ┌──────────────┐
       └──────────────────►│Event         │
                           │Evaluator     │
                           └──────┬───────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
            ┌──────────────┐          ┌──────────────┐
            │Alert Layer   │          │Logging Layer │
            │(Popup)       │          │(access_log)  │
            └──────────────┘          └──────────────┘
```

### Component Responsibilities

| Component | Purpose |
|-----------|---------|
| **Configuration Manager** | Parses and validates `config.json` |
| **Policy Manager** | Evaluates authorization for (group, path, operation) triples |
| **User Manager** | Maps Windows usernames to configured groups |
| **Audit Policy Manager** | Enables Windows Object Access auditing on monitored paths |
| **Event Log Reader** | Polls Security Event Log, applies noise filters, detects renames |
| **Event Evaluator** | Orchestrates policy checks and routes to alert/logging layers |
| **Alert Layer** | Displays real-time popup notifications |
| **Logging Layer** | Appends structured records to `access_log.txt` |

## Installation

### Prerequisites

- **Windows 11** (required for Event ID 4663/4659 monitoring)
- **Python 3.8+**
- **Administrator privileges** (required for audit policy configuration)

### Setup

1. **Clone or download this repository**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

   Dependencies:
   - `pywin32==306` - Windows API access (Event Log, Security)
   - `plyer==2.1.0` - Cross-platform popup notifications
   - `hypothesis==6.112.2` - Property-based testing (dev/test only)
   - `pytest==8.3.3` - Testing framework (dev/test only)

3. **Configure the system** (see Configuration section below)

## Configuration

### Configuration File Format

Create a `config.json` file with the following structure:

```json
{
  "groups": [
    {
      "id": "admin",
      "name": "Administrators",
      "description": "Full access to all folders"
    },
    {
      "id": "user",
      "name": "Standard Users",
      "description": "Limited access"
    }
  ],
  "users": [
    {
      "username": "your_windows_username",
      "group_id": "user"
    }
  ],
  "permissions": [
    {
      "group_id": "admin",
      "path": "C:\\Path\\To\\AdminFolder",
      "allowed_operations": ["READ", "WRITE", "CREATE", "DELETE", "RENAME"]
    },
    {
      "group_id": "user",
      "path": "C:\\Path\\To\\PublicFolder",
      "allowed_operations": ["READ"]
    }
  ],
  "log_file_path": "C:\\Path\\To\\access_log.txt"
}
```

### Configuration Fields

#### Groups
- `id` (string, required): Unique identifier for the group
- `name` (string, required): Display name shown in alerts and logs
- `description` (string, optional): Human-readable description

#### Users
- `username` (string, required): Windows username (case-insensitive)
- `group_id` (string, required): Must reference an existing group `id`

#### Permissions
- `group_id` (string, required): Group this permission applies to
- `path` (string, required): Absolute Windows path to monitor
- `allowed_operations` (array, required): List of allowed operations
  - Valid operations: `READ`, `WRITE`, `CREATE`, `DELETE`, `RENAME`

#### Log File Path
- `log_file_path` (string, required): Absolute path where audit logs will be written

### Path Prefix Matching

Permissions use **prefix matching**: a permission on a folder automatically covers all files and subfolders within it.

Example:
```json
{
  "group_id": "user",
  "path": "C:\\Company\\Projects",
  "allowed_operations": ["READ", "WRITE"]
}
```

This grants the `user` group READ and WRITE access to:
- `C:\Company\Projects\file.txt`
- `C:\Company\Projects\subfolder\document.docx`
- All other files and folders under `C:\Company\Projects`

## Usage

### Starting the System

**IMPORTANT**: Must be run as Administrator

1. Open **Command Prompt** or **PowerShell** as Administrator:
   - Right-click → "Run as administrator"

2. Navigate to the project directory:
   ```bash
   cd "C:\Path\To\Final project"
   ```

3. Run the system:
   ```bash
   python main.py config.json
   ```

4. You should see:
   ```
   User Group Access Control — monitoring started.
   Log file : C:\Path\To\access_log.txt
   Watching paths:
     • C:\Path\To\AdminFolder
     • C:\Path\To\PublicFolder
   Press Ctrl+C to stop.
   ```

### Stopping the System

Press `Ctrl+C` in the terminal to gracefully shut down the system.

### Testing Unauthorized Access

1. **Start the system** as Administrator
2. **Open File Explorer** as your configured user
3. **Navigate to a restricted folder** (e.g., AdminFolder if you're in the "user" group)
4. **Observe**:
   - Popup alert appears immediately
   - Entry is written to `access_log.txt`

### Log File Format

Each unauthorized access attempt is logged in this format:

```
================================================================================
  UNAUTHORIZED ACCESS DETECTED
================================================================================
Timestamp : 2026-04-30 15:36:10
User      : username
Group     : user (Standard Users)
Operation : DELETE
Path      : C:\Users\username\Documents\GMU\740\Files\AdminFolder\file.txt
Item      : file.txt
================================================================================
This event has been logged to the access log file.
================================================================================
```

## How It Works

### Event Monitoring

The system monitors two Windows Security Event Log event types:

1. **Event ID 4663** - "An attempt was made to access an object"
   - Captures READ, WRITE, CREATE operations
   - Used for rename detection (DELETE permission request + WRITE on parent)

2. **Event ID 4659** - "A handle to an object was requested with intent to delete"
   - Captures actual file/folder deletions
   - Critical for detecting permanent deletions (Shift+Delete)

### Noise Filtering

The system applies intelligent filters to exclude background noise:

| Filter | Purpose |
|--------|---------|
| System accounts | Excludes `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `DWM-*`, `UMFD-*` |
| Machine accounts | Excludes usernames ending with `$` |
| Background processes | Excludes Search Indexer, Windows Defender, OneDrive, etc. |
| ReadAttributes-only | Excludes thumbnail generation and metadata reads (0x80 mask) |
| Log file self-reference | Excludes the system's own log file writes |
| Non-watched paths | Only processes events for configured paths |

### Rename Detection

The system uses **event correlation** to distinguish renames from deletions:

1. **File/Folder Rename**:
   - Windows generates: DELETE event (old name) + WRITE event (parent folder)
   - System correlates these within 100ms window
   - Logs as: `RENAME` operation

2. **Actual Deletion**:
   - Windows generates: Event ID 4659 (deletion intent)
   - System logs immediately as: `DELETE` operation

### Folder Enumeration Filtering

When you open a folder in File Explorer, Windows generates READ events for all child items. The system filters these to prevent false positives:

- **Tracks folder opens** (Traverse/Execute access)
- **Suppresses child READ events** within 100ms of parent folder open
- **Allows direct child access** (e.g., from Recent folders or typed paths)
- **Duplicate suppression** for same folder READ events (2-second window)

### Event Log Position Persistence

The system saves its position in the Windows Event Log to `event_reader_state.txt`:

- **First run**: Starts from the latest event (skips all history)
- **Subsequent runs**: Resumes from where it left off
- **Prevents**: Reprocessing old events after restart

## Known Limitations

### 1. Cannot Detect READ During File Edits

**Issue**: When editing a file (open → modify → save), the system logs only the WRITE operation, not the READ.

**Cause**: Windows does not generate separate Event ID 4663 entries for READ and WRITE during file edits. A single event with mask `0x6` (WRITE+CREATE) is generated.

**Impact**: Audit trail shows file was modified but not that content was read first.

**Workaround**: None. This is a Windows Event Log limitation.

### 2. Cannot Reliably Detect Folder Creation

**Issue**: Creating a new folder shows as a READ operation on the new folder, not as a CREATE operation.

**Cause**: Windows generates a WRITE event on the **parent folder** when a subfolder is created. This WRITE is indistinguishable from other parent folder modifications. The first detectable event is when the user opens/views the new folder (READ event).

**Impact**: Folder creation is logged as READ on first access, not as CREATE at creation time.

**Workaround**: None. This is a Windows Event Log limitation.

### 3. Correlation Window Timing

**Issue**: Rename detection uses a 100ms correlation window. Very slow operations may exceed this window.

**Cause**: The system correlates DELETE and WRITE events within 100ms to detect renames. If the OS takes longer than 100ms between these events, the correlation may fail.

**Impact**: Rare edge case where a rename might be logged as DELETE + CREATE instead of RENAME.

**Workaround**: Increase the correlation window in `event_log_reader.py` if needed.

### 4. Event ID 4659 for File Deletions Only

**Issue**: Folder deletions may not generate Event ID 4659 immediately.

**Cause**: Windows generates Event ID 4659 reliably for file deletions but may delay or omit it for folder deletions.

**Impact**: Folder deletions are logged on system shutdown (orphaned DELETE emission) rather than immediately.

**Workaround**: None. This is a Windows Event Log behavior.

## Testing

### Running Tests

The project includes comprehensive test suites:

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_bug_condition_exploration.py

# Run with verbose output
pytest -v

# Run property-based tests
pytest tests/test_preservation_properties.py
```

### Test Structure

- `tests/test_bug_condition_exploration.py` - Integration tests for bug fixes
- `tests/test_preservation_properties.py` - Property-based tests for regression prevention
- Uses `hypothesis` for property-based testing
- Uses `pytest` as the test runner

### Manual Testing Procedure

1. **Start the system** as Administrator
2. **Test authorized access**:
   - Access a folder your group has permission for
   - Verify: No alert, no log entry
3. **Test unauthorized access**:
   - Access a folder your group does NOT have permission for
   - Verify: Popup alert appears, log entry written
4. **Test file operations**:
   - Create a file in a restricted folder → Verify: CREATE logged
   - Edit a file in a restricted folder → Verify: WRITE logged
   - Rename a file in a restricted folder → Verify: RENAME logged
   - Delete a file in a restricted folder → Verify: DELETE logged
5. **Test folder operations**:
   - Open a restricted folder → Verify: READ logged (folder only, not children)
   - Rename a restricted folder → Verify: RENAME logged
   - Delete a restricted folder → Verify: DELETE logged (on shutdown)

## Troubleshooting

### "This program must be run as Administrator"

**Solution**: Right-click Command Prompt or PowerShell and select "Run as administrator"

### No events are being logged

**Possible causes**:
1. **Audit policy not enabled**: The system enables this automatically, but verify with:
   ```bash
   auditpol /get /subcategory:"File System"
   ```
   Should show: `Success and Failure`

2. **SACL not set on monitored paths**: The system sets this automatically, but verify with:
   ```bash
   icacls "C:\Path\To\Folder" /t
   ```
   Look for audit entries (SACL)

3. **Path mismatch**: Ensure paths in `config.json` exactly match the actual folder paths (case-insensitive but must be exact)

### Old events are being reprocessed

**Solution**: Delete `event_reader_state.txt` and restart the system. It will start from the latest event.

### Too many READ events for the same folder

**Cause**: Windows generates multiple READ events when browsing folders.

**Solution**: The system includes 2-second duplicate suppression. If still seeing too many events, increase the suppression window in `event_log_reader.py`:

```python
# In _process_4663_event method
DUPLICATE_SUPPRESSION_WINDOW = 2.0  # Increase this value
```

### Background processes triggering alerts

**Cause**: Windows Search Indexer, Windows Defender, or other background services accessing monitored folders.

**Solution**: The system filters common background processes. If you identify additional processes, add them to `_IGNORED_PROCESSES` in `event_log_reader.py`:

```python
_IGNORED_PROCESSES = {
    "searchindexer.exe",
    "msmpeng.exe",
    "onedrive.exe",
    "your_process_here.exe",  # Add new process
}
```

### Popup alerts not appearing

**Possible causes**:
1. **Notification permissions**: Ensure Python is allowed to show notifications in Windows Settings
2. **Focus Assist enabled**: Disable Focus Assist in Windows Settings
3. **plyer library issue**: Check console for error messages

**Workaround**: Even if popups fail, log entries are still written to `access_log.txt`

## Project Structure

```
.
├── user_group_access_control/       # Main package
│   ├── __init__.py
│   ├── alert_layer.py               # Popup notifications
│   ├── audit_policy_manager.py      # Windows audit policy configuration
│   ├── configuration_manager.py     # Config file parsing and validation
│   ├── event_evaluator.py           # Policy evaluation and routing
│   ├── event_log_reader.py          # Event Log monitoring and filtering
│   ├── exceptions.py                # Custom exception types
│   ├── logging_layer.py             # Audit log file writing
│   ├── models.py                    # Data models (Group, Permission, etc.)
│   ├── policy_manager.py            # Authorization logic
│   └── user_manager.py              # User-to-group mapping
├── tests/                           # Test suite
│   ├── test_bug_condition_exploration.py
│   └── test_preservation_properties.py
├── .kiro/                           # Spec files (development documentation)
│   └── specs/
│       ├── file-system-logging-bugs/
│       └── user-group-access-control/
├── main.py                          # System entry point
├── config.json                      # Configuration file (customize this)
├── requirements.txt                 # Python dependencies
├── access_log.txt                   # Audit log (generated at runtime)
├── event_reader_state.txt           # Event Log position (generated at runtime)
├── README.md                        # This file
└── SOLUTION_SUMMARY.md              # Bug fix summary
```

## Development

### Spec-Driven Development

This project was developed using spec-driven development methodology:

1. **Requirements Document** (`.kiro/specs/user-group-access-control/requirements.md`)
   - User stories and acceptance criteria
   - Formal requirements for each component

2. **Design Document** (`.kiro/specs/user-group-access-control/design.md`)
   - Architecture diagrams
   - Component interfaces
   - Algorithmic pseudocode
   - Correctness properties

3. **Bugfix Spec** (`.kiro/specs/file-system-logging-bugs/`)
   - Bug condition analysis
   - Root cause investigation
   - Fix implementation strategy
   - Property-based testing approach

### Key Implementation Insights

1. **Event ID 4659 is critical**: Windows uses Event ID 4659 for actual deletions, not Event ID 4663 with DELETE mask. This was discovered through extensive testing.

2. **Rename detection requires correlation**: Windows doesn't have a RENAME event. Renames generate DELETE (old name) + WRITE (parent folder) events that must be correlated.

3. **Folder enumeration is noisy**: Opening a folder generates READ events for all children. Filtering requires tracking folder opens and suppressing child events within a time window.

4. **Event Log position persistence is essential**: Without it, every restart reprocesses all historical events, causing false alerts.

5. **Background process filtering is necessary**: Windows Search Indexer, Defender, and other services constantly access folders. These must be filtered to avoid noise.

## License

This is a prototype demonstration project developed for educational purposes.

## Credits

Developed as part of GMU CS 740 coursework, demonstrating:
- Windows Security Event Log monitoring
- Real-time access control enforcement
- Property-based testing methodology
- Spec-driven development practices

## Support

For issues or questions:
1. Check the Troubleshooting section above
2. Review the spec files in `.kiro/specs/` for detailed technical documentation
3. Examine `SOLUTION_SUMMARY.md` for bug fix details

---

**Last Updated**: April 30, 2026
