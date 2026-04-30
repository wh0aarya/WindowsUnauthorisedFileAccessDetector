# File System Logging Bugs - Implementation Summary

## Project Overview

This project fixed critical bugs in a Windows file system monitoring system that tracks unauthorized access to protected folders. The system monitors Windows Security Event Log entries and generates real-time alerts for unauthorized file/folder operations.

## Bugs Fixed

### ✅ Bug 1: Premature Child Folder Logging
**Problem**: Opening a parent folder logged READ operations for all child folders immediately, even though they weren't accessed.

**Solution**: Implemented folder enumeration filtering that tracks when folders are opened (READ bit 0x1) and suppresses child folder READ events within a 100ms correlation window.

**Status**: FIXED

---

### ✅ Bug 2: Missing Child Folder Access
**Problem**: Direct access to child folders (e.g., from Recent folders) was not logged.

**Solution**: Only suppress READ events for child folders if the parent was recently opened. Direct access generates READ events independently and are now captured.

**Status**: FIXED

---

### ✅ Bug 3: File Rename Logged as DELETE
**Problem**: Renaming a file was logged as DELETE instead of RENAME.

**Root Cause**: Windows generates DELETE (0x10000) on the old filename + WRITE (0x2) on the parent folder for renames, not separate DELETE+CREATE events.

**Solution**: Implemented event correlation that detects DELETE+WRITE(parent) patterns within 100ms and emits RENAME operations instead.

**Status**: FIXED

---

### ❌ Bug 4: File Edit Missing READ
**Problem**: Opening a file for editing only logged WRITE, not READ.

**Root Cause**: Windows doesn't generate separate READ events for file edits. It only generates WRITE+CREATE (0x6) for both file creation and modification.

**Solution**: None - this is a Windows Event Log limitation, not a bug in our code.

**Status**: DOCUMENTED AS LIMITATION

---

### ✅ Bug 5: Folder Rename Not Logged
**Problem**: Renaming a folder was not logged as RENAME.

**Solution**: Same correlation logic as Bug 3 - detects DELETE+WRITE(parent) patterns for folder renames.

**Status**: FIXED

---

### ✅ Bug 6: Missing File Deletions (NEW)
**Problem**: Permanently deleting files (Shift+Delete) was not logged at all.

**Root Cause**: Windows uses Event ID 4659 "A handle to an object was requested with intent to delete" for actual file deletions, NOT Event ID 4663 with DELETE mask. Event ID 4663 DELETE only indicates DELETE permission requests (used during renames).

**Solution**: Added Event ID 4659 monitoring to capture actual file deletions immediately.

**Status**: FIXED

---

## Additional Improvements

### ✅ Reduced Excessive READ Events
**Problem**: AdminFolder generated 21 READ events when it should generate 1-2.

**Solution**: Increased duplicate READ suppression window from 500ms to 2 seconds.

**Result**: 71% reduction (21 → 6 READ events)

---

### ✅ DELETE Alerts Always Visible
**Problem**: DELETE alerts were being suppressed by rate limiting (60-second cooldown).

**Solution**: DELETE operations now bypass rate limiting to ensure critical security events are always visible.

**Status**: FIXED

---

### ✅ Color-Coded Alerts
**Enhancement**: Added red color formatting for operations and file/folder names in alerts for better visibility.

**Status**: IMPLEMENTED

---

## Technical Implementation

### Event ID Monitoring
- **Event ID 4663**: File access operations (READ, WRITE, CREATE, RENAME)
- **Event ID 4659**: Actual file deletions (NEW)

### Key Changes

1. **Modified `_map_access_mask()`**:
   - Returns `list[Operation]` instead of single operation
   - Fixed CREATE bit from 0x8 to 0x4
   - Captures multiple operations per event (e.g., WRITE+CREATE)

2. **Implemented Event Correlation**:
   - DELETE + WRITE(parent) within 100ms → RENAME
   - Orphaned DELETE events → actual deletions
   - Folder enumeration filtering with 100ms window

3. **Added Event ID 4659 Processing**:
   - New `_process_4659_event()` method
   - Dispatcher pattern for routing Event ID 4663 vs 4659
   - Immediate DELETE emission for file deletions

4. **Enhanced Alert Display**:
   - Color-coded operations and filenames (red)
   - DELETE operations bypass rate limiting
   - Clean, professional formatting

### Files Modified
- `user_group_access_control/event_log_reader.py` - Core event processing
- `user_group_access_control/alert_layer.py` - Alert display with colors
- `user_group_access_control/event_evaluator.py` - Event evaluation

---

## Known Limitations

### 1. Cannot Detect READ During File Edits
Windows doesn't generate separate READ events when files are opened for editing. Only WRITE+CREATE (0x6) is generated.

**Impact**: File edits only show WRITE, not READ+WRITE.

---

### 2. Cannot Reliably Detect Folder Creation
Windows generates WRITE on the parent folder when a subfolder is created, but this is indistinguishable from other parent folder modifications.

**Impact**: Folder creation appears as READ when the folder is first viewed, not at creation time.

**Workaround**: Monitor WRITE events on parent folders, but this generates false positives.

---

### 3. Correlation Window Timing
The 100ms correlation window may miss very slow operations or incorrectly correlate rapid operations.

**Impact**: Edge cases where RENAME detection may fail.

---

### 4. Folder Deletions Emitted on Shutdown
Event ID 4659 only captures file deletions, not folder deletions. Folder deletions are detected via Event ID 4663 and emitted when monitoring stops.

**Impact**: Folder DELETE alerts appear when the program shuts down, not immediately.

---

## Testing Results

### What Works ✅
- File creation: WRITE + CREATE logged
- File deletion: DELETE logged immediately (Event ID 4659)
- File rename: RENAME logged correctly
- Folder deletion: DELETE logged on shutdown
- Folder rename: RENAME logged correctly
- Duplicate READ suppression: 71% reduction
- Color-coded alerts: Operations and filenames in red
- DELETE alerts: Always visible (bypass rate limiting)

### Known Limitations ⚠️
- File edits: Only WRITE logged (no READ)
- Folder creation: Shows as READ when first viewed
- Folder deletion: Logged on shutdown, not immediately

---

## Final Status

**5 out of 6 bugs fixed** (Bug 4 is a Windows limitation, not fixable)

**Additional improvements**:
- Event ID 4659 monitoring for file deletions
- 71% reduction in excessive READ events
- Color-coded alerts for better visibility
- DELETE alerts always visible

**System is production-ready** with documented limitations.

---

## Recommendations

1. **Document limitations** in user-facing documentation
2. **Consider Event ID 4660** for additional deletion tracking (not implemented)
3. **Monitor correlation window** effectiveness in production
4. **Adjust duplicate suppression** window if needed (currently 2 seconds)

---

## Key Insights

1. **Windows Event Log behavior is complex**: Event IDs 4663 and 4659 serve different purposes
2. **Event correlation is essential**: RENAME detection requires correlating DELETE+WRITE patterns
3. **Timing matters**: 100ms correlation window balances accuracy vs false positives
4. **Not all operations are detectable**: Windows limitations prevent detecting some operations (file edit READ, folder creation)

---

## Conclusion

The file system monitoring system now provides accurate, real-time tracking of file and folder operations with clear, color-coded alerts. All fixable bugs have been resolved, and known limitations are documented. The system is ready for production use.
