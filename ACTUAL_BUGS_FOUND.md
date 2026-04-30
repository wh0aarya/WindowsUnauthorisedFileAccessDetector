# Actual Bugs Found Through Investigation

## Summary

Through extensive testing with real Windows Event Log data, we discovered that our original bug hypothesis was **partially incorrect**. The actual Windows behavior is different from what we expected.

## Original Hypothesis vs Reality

### Original Hypothesis (WRONG)
- Windows generates separate DELETE and CREATE events for renames
- Windows generates separate READ and WRITE events for file edits
- Bit `0x8` is the CREATE bit

### Actual Reality (CORRECT)
- **Renames**: Windows generates `DELETE` (0x10000) on old name + `WRITE` (0x2) on parent folder
- **File edits**: Windows generates `0x6` (WRITE+CREATE bits) for both creation and modification
- **CREATE bit**: Bit `0x4` (AppendData/AddSubdirectory), not `0x8`

## Real Bugs Confirmed

### Bug 1: Premature Child Folder Logging ✅ CONFIRMED
- **Cause**: Folder enumeration filtering was checking wrong bit (0x20 Traverse instead of 0x1 ListDirectory)
- **Fix**: Track folders with READ bit (0x1) and suppress child READ events within correlation window

### Bug 2: Missing Child Folder Access ✅ CONFIRMED  
- **Cause**: Same as Bug 1 - enumeration filtering was too aggressive
- **Fix**: Only suppress if parent was recently opened

### Bug 3: File Rename Logged as DELETE ✅ CONFIRMED
- **Cause**: Windows generates DELETE+WRITE(parent), not DELETE+CREATE
- **Fix**: Correlate DELETE with WRITE on parent folder within 100ms window

### Bug 4: File Edit Missing READ ❌ NOT A BUG
- **Reality**: Windows doesn't generate separate READ events for file edits
- **Windows Behavior**: Generates `0x6` (WRITE+CREATE) for both file creation and modification
- **Conclusion**: This is how Windows works - we cannot detect READ operations during file edits

### Bug 5: Folder Rename Not Logged ✅ CONFIRMED
- **Cause**: Same as Bug 3 - Windows generates DELETE+WRITE(parent)
- **Fix**: Same correlation logic as file renames

## Access Mask Patterns Discovered

### File Operations
- **Create file**: `0x6` (WRITE + CREATE)
- **Read file**: `0x1` (READ)
- **Write file**: `0x6` (WRITE + CREATE) - same as create!
- **Rename file**: `0x10000` (DELETE) on old + `0x2` (WRITE) on parent
- **Delete file**: `0x10000` (DELETE)

### Folder Operations
- **Open folder**: `0x1` (READ/ListDirectory)
- **Create folder**: `0x2` (WRITE) on parent folder
- **Rename folder**: `0x10000` (DELETE) on old + `0x2` (WRITE) on parent
- **Delete folder**: `0x10000` (DELETE)

### Noise Events (Filtered)
- `0x80` (ReadAttributes) - filtered
- `0x20000` (READ_CONTROL) - filtered

## Implementation Changes Made

1. **Fixed `_map_access_mask()`**:
   - Changed CREATE bit from `0x8` to `0x4`
   - Removed `0x4` from WRITE detection (it's CREATE, not WRITE)

2. **Fixed RENAME detection**:
   - Changed from DELETE+CREATE correlation to DELETE+WRITE(parent) correlation
   - Check if WRITE is on a folder and if there's a recent DELETE of a child

3. **Fixed folder enumeration filtering**:
   - Changed from tracking Traverse bit (0x20) to READ bit (0x1)
   - Track folders when they have READ access, not Traverse

4. **Added orphaned DELETE emission**:
   - DELETEs that aren't followed by WRITE on parent within 100ms are emitted as actual deletions

## Limitations

### 1. Cannot Detect READ During File Edits
Windows doesn't generate separate READ events when a file is opened for editing. Only WRITE+CREATE (0x6) events are generated for both file creation and modification. This is a Windows Event Log limitation, not a bug in our implementation.

**Impact**: When a user opens a file in an editor, modifies it, and saves it, only the WRITE operation is logged. The READ operation that occurs when the file is opened is not captured.

### 2. Cannot Reliably Detect Folder Creation
Windows generates WRITE events on the **parent folder** when a subfolder is created, but these events are indistinguishable from other parent folder modifications (e.g., file creation, permission changes). 

**Impact**: Folder creation typically appears as a READ event when the newly created folder is first accessed/viewed by the user, not at the moment of creation. This means:
- Creating a folder and immediately viewing it → logged as READ
- Creating a folder without viewing it → not logged at all

**Why This Happens**: 
- Event ID 4663 generates WRITE on the parent folder (e.g., AdminFolder) when a child folder is created
- We cannot distinguish this WRITE from other operations on the parent folder
- The first detectable event is when the user opens/views the new folder (READ event)

### 3. Correlation Window Timing
The 100ms correlation window for RENAME detection may miss very slow operations or incorrectly correlate unrelated operations if they occur within the window.

**Impact**: 
- Very slow rename operations (>100ms between DELETE and WRITE) may be logged as separate DELETE and WRITE operations instead of RENAME
- Rapid successive operations within 100ms may be incorrectly correlated as RENAME

### 4. Event ID 4659 for File Deletions Only
Windows generates Event ID 4659 "A handle to an object was requested with intent to delete" for **file deletions** but not for **folder deletions**. 

**Impact**: 
- File deletions are captured immediately via Event ID 4659 ✅
- Folder deletions are detected via Event ID 4663 DELETE events and emitted when the monitoring stops (on shutdown) ⚠️

**Why This Happens**: Windows uses different event patterns for file vs folder deletions. Folder deletions generate Event ID 4663 DELETE events that must be correlated to distinguish from RENAME operations.

## Testing Results

From `test_file_operations.py`:
- ✅ File creation detected: `0x6 = WRITE + CREATE`
- ✅ File read detected: `0x1 = READ`
- ✅ File write detected: `0x6 = WRITE + CREATE`
- ✅ File rename detected: `0x10000 = DELETE` + `0x2 = WRITE` on parent
- ✅ File deletion detected: `0x10000 = DELETE`

## Conclusion

The implementation has been updated to match the actual Windows Event Log behavior. The main insight is that **Windows doesn't work the way we initially thought** - renames are DELETE+WRITE(parent), not DELETE+CREATE, and file edits don't generate separate READ events.
