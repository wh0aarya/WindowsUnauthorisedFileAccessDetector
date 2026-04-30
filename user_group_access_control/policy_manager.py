import os
from user_group_access_control.models import Group, Permission


class PolicyManager:
    def __init__(self) -> None:
        self._groups: list[Group] = []
        self._permissions: list[Permission] = []

    def register_groups(self, groups: list[Group]) -> None:
        """Store the list of groups."""
        self._groups = list(groups)

    def register_permissions(self, permissions: list[Permission]) -> None:
        """Store the list of permissions."""
        self._permissions = list(permissions)

    def is_authorized(self, group_id: str, path: str, operation: str) -> bool:
        """
        Return True if the given group is authorized to perform the operation on path.

        Uses case-insensitive prefix matching via os.path.normcase.
        A permission on a folder covers all files and subfolders inside it,
        but the prefix match must be on a proper path boundary to avoid
        false positives (e.g. C:\\Admin must not match C:\\AdminOther).
        """
        normalized_path = os.path.normcase(path)

        for perm in self._permissions:
            if perm.group_id != group_id:
                continue

            normalized_perm_path = os.path.normcase(perm.path)

            # Check prefix match on a proper path boundary.
            # The accessed path must either equal the permission path exactly,
            # or start with the permission path followed by a separator.
            if normalized_path == normalized_perm_path or normalized_path.startswith(
                normalized_perm_path + os.sep
            ):
                if operation in perm.allowed_operations:
                    return True

        return False

    def get_watched_paths(self) -> list[str]:
        """Return the unique set of permission paths."""
        seen: set[str] = set()
        result: list[str] = []
        for perm in self._permissions:
            if perm.path not in seen:
                seen.add(perm.path)
                result.append(perm.path)
        return result
