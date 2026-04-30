from user_group_access_control.models import UserRecord


class UserManager:
    """Maps Windows usernames to configured group identifiers.

    Usernames are matched case-insensitively, consistent with Windows
    username semantics.
    """

    def __init__(self) -> None:
        # Stores lowercased username -> group_id
        self._user_map: dict[str, str] = {}

    def register_users(self, users: list[UserRecord]) -> None:
        """Store a lowercased username → group_id mapping for each UserRecord.

        Args:
            users: List of UserRecord objects to register.
        """
        self._user_map = {record.username.lower(): record.group_id for record in users}

    def resolve_group(self, username: str) -> str | None:
        """Return the group_id for the given username, or None if not registered.

        Lookup is case-insensitive: "Alice", "alice", and "ALICE" all resolve
        to the same group.

        Args:
            username: The Windows username to look up.

        Returns:
            The group_id associated with the username, or None if not found.
        """
        return self._user_map.get(username.lower())
