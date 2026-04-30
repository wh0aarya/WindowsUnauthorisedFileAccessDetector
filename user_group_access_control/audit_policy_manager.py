"""
AuditPolicyManager — configures Windows OS-level auditing on monitored paths.

Requires administrator privileges to:
  - Enable the "File System" audit subcategory via auditpol
  - Set a SACL on each monitored path via win32security (pywin32)
"""

import subprocess
import sys

try:
    import win32security
    import win32api
    import win32con
    import ntsecuritycon
    _WIN32_AVAILABLE = True
except ImportError:
    _WIN32_AVAILABLE = False


def _enable_security_privilege() -> bool:
    """
    Enable SeSecurityPrivilege on the current process token.

    This privilege is required to read or write the SACL of a file/folder
    via GetFileSecurity / SetFileSecurity with SACL_SECURITY_INFORMATION.
    It is held by Administrators but must be explicitly enabled.

    Returns True if the privilege was successfully enabled, False otherwise.
    """
    if not _WIN32_AVAILABLE:
        return False
    try:
        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY,
        )
        luid = win32security.LookupPrivilegeValue(None, "SeSecurityPrivilege")
        win32security.AdjustTokenPrivileges(
            token,
            False,
            [(luid, win32con.SE_PRIVILEGE_ENABLED)],
        )
        return True
    except Exception as exc:
        print(
            f"AuditPolicyManager: failed to enable SeSecurityPrivilege: {exc}",
            file=sys.stderr,
        )
        return False


class AuditPolicyManager:
    """
    Configures Windows OS-level auditing on monitored paths so that file and
    folder access events are written to the Windows Security Event Log
    (Event ID 4663).
    """

    def enable_auditing(self, paths: list[str]) -> None:
        """
        Enable Object Access auditing for both success and failure events, then
        set a SACL on each path so that Windows logs access attempts.

        Steps:
          1. Run ``auditpol /set /subcategory:"File System" /success:enable
             /failure:enable`` to activate the audit policy.
          2. For each path, add an audit ACE for "Everyone" covering all access
             types (GENERIC_ALL) with CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
             so that both folder opens and file accesses within watched paths are
             audited.

        Requires administrator privileges.
        """
        # Step 1: Enable the File System audit subcategory via auditpol.
        try:
            subprocess.run(
                [
                    "auditpol",
                    "/set",
                    '/subcategory:File System',
                    "/success:enable",
                    "/failure:enable",
                ],
                check=True,
            )
        except Exception as exc:
            print(
                f"AuditPolicyManager: failed to set auditpol policy: {exc}",
                file=sys.stderr,
            )

        if not _WIN32_AVAILABLE:
            print(
                "AuditPolicyManager: win32security is not available; "
                "skipping SACL configuration.",
                file=sys.stderr,
            )
            return

        # Enable SeSecurityPrivilege — required to read/write SACLs.
        _enable_security_privilege()

        # Step 2: Set a SACL on each path.
        for path in paths:
            try:
                self._set_sacl(path)
            except Exception as exc:
                print(
                    f"AuditPolicyManager: failed to set SACL on {path!r}: {exc}",
                    file=sys.stderr,
                )

    def disable_auditing(self, paths: list[str]) -> None:
        """
        Remove the SACL ACEs added by ``enable_auditing`` from each path by
        replacing the SACL with an empty one.
        """
        if not _WIN32_AVAILABLE:
            print(
                "AuditPolicyManager: win32security is not available; "
                "skipping SACL removal.",
                file=sys.stderr,
            )
            return

        # Enable SeSecurityPrivilege — required to read/write SACLs.
        _enable_security_privilege()

        for path in paths:
            try:
                self._clear_sacl(path)
            except Exception as exc:
                print(
                    f"AuditPolicyManager: failed to clear SACL on {path!r}: {exc}",
                    file=sys.stderr,
                )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _set_sacl(self, path: str) -> None:
        """Add an audit ACE for Everyone (GENERIC_ALL, success+failure) to path."""
        # Retrieve the existing security descriptor (SACL portion).
        try:
            sd = win32security.GetFileSecurity(
                path, win32security.SACL_SECURITY_INFORMATION
            )
        except Exception as exc:
            print(
                f"AuditPolicyManager: GetFileSecurity failed for {path!r}: {exc}",
                file=sys.stderr,
            )
            return

        # Get or create the SACL.
        sacl = sd.GetSecurityDescriptorSacl()
        if sacl is None:
            sacl = win32security.ACL()

        # Resolve the SID for "Everyone".
        try:
            everyone_sid, _, _ = win32security.LookupAccountName(None, "Everyone")
        except Exception as exc:
            print(
                f"AuditPolicyManager: LookupAccountName('Everyone') failed: {exc}",
                file=sys.stderr,
            )
            return

        # Add the audit ACE.
        # Signature: AddAuditAccessAce(revision, access_mask, sid,
        #                               audit_success, audit_failure)
        sacl.AddAuditAccessAce(
            win32security.ACL_REVISION,
            ntsecuritycon.GENERIC_ALL,
            everyone_sid,
            True,   # audit_success
            True,   # audit_failure
        )

        # Apply inheritance flags by using AddAuditAccessAceEx when available,
        # otherwise fall back to the basic AddAuditAccessAce already called above.
        # AddAuditAccessAceEx supports inheritance flags directly.
        # Re-create the SACL with the correct ACE using AceEx.
        sacl_ex = win32security.ACL()
        inherit_flags = (
            win32security.CONTAINER_INHERIT_ACE | win32security.OBJECT_INHERIT_ACE
        )
        sacl_ex.AddAuditAccessAceEx(
            win32security.ACL_REVISION_DS,
            inherit_flags,
            ntsecuritycon.GENERIC_ALL,
            everyone_sid,
            True,   # audit_success
            True,   # audit_failure
        )

        # Write the updated SACL back to the security descriptor.
        sd.SetSecurityDescriptorSacl(True, sacl_ex, False)

        try:
            win32security.SetFileSecurity(
                path, win32security.SACL_SECURITY_INFORMATION, sd
            )
        except Exception as exc:
            print(
                f"AuditPolicyManager: SetFileSecurity failed for {path!r}: {exc}",
                file=sys.stderr,
            )

    def _clear_sacl(self, path: str) -> None:
        """Replace the SACL on path with an empty ACL (removes all audit ACEs)."""
        try:
            sd = win32security.GetFileSecurity(
                path, win32security.SACL_SECURITY_INFORMATION
            )
        except Exception as exc:
            print(
                f"AuditPolicyManager: GetFileSecurity failed for {path!r}: {exc}",
                file=sys.stderr,
            )
            return

        empty_sacl = win32security.ACL()
        sd.SetSecurityDescriptorSacl(True, empty_sacl, False)

        try:
            win32security.SetFileSecurity(
                path, win32security.SACL_SECURITY_INFORMATION, sd
            )
        except Exception as exc:
            print(
                f"AuditPolicyManager: SetFileSecurity failed for {path!r}: {exc}",
                file=sys.stderr,
            )
