"""
Configuration Manager for User Group Access Control.

Loads, validates, and exposes the developer-defined group and permission
configuration from a JSON file or a Python dict.
"""

import json
import os
from typing import Any

from .exceptions import ConfigurationError
from .models import Config, Group, Permission, UserRecord

# Valid operation values
VALID_OPERATIONS = {"READ", "WRITE", "DELETE", "RENAME", "CREATE"}


class ConfigurationManager:
    """Parses and validates group/permission definitions."""

    def load_from_file(self, file_path: str) -> Config:
        """Load and validate a Config from a JSON file.

        Args:
            file_path: Path to the JSON configuration file.

        Returns:
            A validated Config object.

        Raises:
            ConfigurationError: If the file is missing, contains malformed JSON,
                fails schema validation, has duplicate group IDs, or contains a
                UserRecord whose group_id does not reference any defined Group.
        """
        if not os.path.exists(file_path):
            raise ConfigurationError(
                f"Configuration file not found: '{file_path}'"
            )

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except json.JSONDecodeError as exc:
            raise ConfigurationError(
                f"Malformed JSON in configuration file '{file_path}': {exc}"
            ) from exc
        except OSError as exc:
            raise ConfigurationError(
                f"Cannot read configuration file '{file_path}': {exc}"
            ) from exc

        return self.load_from_code(raw)

    def load_from_code(self, spec: dict) -> Config:
        """Load and validate a Config from a Python dict.

        Args:
            spec: A dictionary matching the JSON configuration schema.

        Returns:
            A validated Config object.

        Raises:
            ConfigurationError: If the spec fails schema validation, has
                duplicate group IDs, or contains a UserRecord whose group_id
                does not reference any defined Group.
        """
        if not isinstance(spec, dict):
            raise ConfigurationError(
                "Configuration must be a JSON object (dict), "
                f"got {type(spec).__name__}"
            )

        # --- groups ---
        if "groups" not in spec:
            raise ConfigurationError(
                "Configuration is missing required field 'groups'"
            )
        if not isinstance(spec["groups"], list):
            raise ConfigurationError(
                "Field 'groups' must be a list, "
                f"got {type(spec['groups']).__name__}"
            )

        groups: list[Group] = []
        seen_group_ids: set[str] = set()
        for i, g in enumerate(spec["groups"]):
            group = self._parse_group(g, index=i)
            if group.id in seen_group_ids:
                raise ConfigurationError(
                    f"Duplicate group ID '{group.id}' found in 'groups'"
                )
            seen_group_ids.add(group.id)
            groups.append(group)

        # --- users ---
        if "users" not in spec:
            raise ConfigurationError(
                "Configuration is missing required field 'users'"
            )
        if not isinstance(spec["users"], list):
            raise ConfigurationError(
                "Field 'users' must be a list, "
                f"got {type(spec['users']).__name__}"
            )

        users: list[UserRecord] = []
        for i, u in enumerate(spec["users"]):
            user = self._parse_user(u, index=i)
            users.append(user)

        # --- permissions ---
        if "permissions" not in spec:
            raise ConfigurationError(
                "Configuration is missing required field 'permissions'"
            )
        if not isinstance(spec["permissions"], list):
            raise ConfigurationError(
                "Field 'permissions' must be a list, "
                f"got {type(spec['permissions']).__name__}"
            )

        permissions: list[Permission] = []
        for i, p in enumerate(spec["permissions"]):
            perm = self._parse_permission(p, index=i)
            permissions.append(perm)

        # --- log_file_path ---
        if "log_file_path" not in spec:
            raise ConfigurationError(
                "Configuration is missing required field 'log_file_path'"
            )
        log_file_path = spec["log_file_path"]
        if not isinstance(log_file_path, str):
            raise ConfigurationError(
                "Field 'log_file_path' must be a string, "
                f"got {type(log_file_path).__name__}"
            )
        if not log_file_path.strip():
            raise ConfigurationError(
                "Field 'log_file_path' must not be empty"
            )

        config = Config(
            groups=groups,
            users=users,
            permissions=permissions,
            log_file_path=log_file_path,
        )

        self.validate(config)
        return config

    def validate(self, config: Config) -> None:
        """Validate a Config object for referential integrity.

        Checks:
        - No duplicate group IDs.
        - Every UserRecord.group_id references an existing Group.

        Args:
            config: The Config object to validate.

        Raises:
            ConfigurationError: If any validation rule is violated.
        """
        # Check for duplicate group IDs
        seen_ids: set[str] = set()
        for group in config.groups:
            if group.id in seen_ids:
                raise ConfigurationError(
                    f"Duplicate group ID '{group.id}' found in configuration"
                )
            seen_ids.add(group.id)

        # Check that every UserRecord.group_id references an existing group
        for user in config.users:
            if user.group_id not in seen_ids:
                raise ConfigurationError(
                    f"UserRecord for username '{user.username}' references "
                    f"unknown group_id '{user.group_id}'"
                )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_group(self, raw: Any, index: int) -> Group:
        """Parse and validate a single group entry."""
        if not isinstance(raw, dict):
            raise ConfigurationError(
                f"groups[{index}] must be an object, got {type(raw).__name__}"
            )

        # id
        if "id" not in raw:
            raise ConfigurationError(
                f"groups[{index}] is missing required field 'id'"
            )
        gid = raw["id"]
        if not isinstance(gid, str):
            raise ConfigurationError(
                f"groups[{index}].id must be a string, got {type(gid).__name__}"
            )
        if not gid.strip():
            raise ConfigurationError(
                f"groups[{index}].id must not be empty"
            )

        # name
        if "name" not in raw:
            raise ConfigurationError(
                f"groups[{index}] is missing required field 'name'"
            )
        name = raw["name"]
        if not isinstance(name, str):
            raise ConfigurationError(
                f"groups[{index}].name must be a string, got {type(name).__name__}"
            )
        if not name.strip():
            raise ConfigurationError(
                f"groups[{index}].name must not be empty"
            )

        # description (optional, defaults to "")
        description = raw.get("description", "")
        if not isinstance(description, str):
            raise ConfigurationError(
                f"groups[{index}].description must be a string, "
                f"got {type(description).__name__}"
            )

        return Group(id=gid, name=name, description=description)

    def _parse_user(self, raw: Any, index: int) -> UserRecord:
        """Parse and validate a single user entry."""
        if not isinstance(raw, dict):
            raise ConfigurationError(
                f"users[{index}] must be an object, got {type(raw).__name__}"
            )

        # username
        if "username" not in raw:
            raise ConfigurationError(
                f"users[{index}] is missing required field 'username'"
            )
        username = raw["username"]
        if not isinstance(username, str):
            raise ConfigurationError(
                f"users[{index}].username must be a string, "
                f"got {type(username).__name__}"
            )
        if not username.strip():
            raise ConfigurationError(
                f"users[{index}].username must not be empty"
            )

        # group_id
        if "group_id" not in raw:
            raise ConfigurationError(
                f"users[{index}] is missing required field 'group_id'"
            )
        group_id = raw["group_id"]
        if not isinstance(group_id, str):
            raise ConfigurationError(
                f"users[{index}].group_id must be a string, "
                f"got {type(group_id).__name__}"
            )
        if not group_id.strip():
            raise ConfigurationError(
                f"users[{index}].group_id must not be empty"
            )

        return UserRecord(username=username, group_id=group_id)

    def _parse_permission(self, raw: Any, index: int) -> Permission:
        """Parse and validate a single permission entry."""
        if not isinstance(raw, dict):
            raise ConfigurationError(
                f"permissions[{index}] must be an object, "
                f"got {type(raw).__name__}"
            )

        # group_id
        if "group_id" not in raw:
            raise ConfigurationError(
                f"permissions[{index}] is missing required field 'group_id'"
            )
        group_id = raw["group_id"]
        if not isinstance(group_id, str):
            raise ConfigurationError(
                f"permissions[{index}].group_id must be a string, "
                f"got {type(group_id).__name__}"
            )
        if not group_id.strip():
            raise ConfigurationError(
                f"permissions[{index}].group_id must not be empty"
            )

        # path
        if "path" not in raw:
            raise ConfigurationError(
                f"permissions[{index}] is missing required field 'path'"
            )
        path = raw["path"]
        if not isinstance(path, str):
            raise ConfigurationError(
                f"permissions[{index}].path must be a string, "
                f"got {type(path).__name__}"
            )
        if not path.strip():
            raise ConfigurationError(
                f"permissions[{index}].path must not be empty"
            )

        # allowed_operations
        if "allowed_operations" not in raw:
            raise ConfigurationError(
                f"permissions[{index}] is missing required field "
                "'allowed_operations'"
            )
        ops_raw = raw["allowed_operations"]
        if not isinstance(ops_raw, list):
            raise ConfigurationError(
                f"permissions[{index}].allowed_operations must be a list, "
                f"got {type(ops_raw).__name__}"
            )
        if not ops_raw:
            raise ConfigurationError(
                f"permissions[{index}].allowed_operations must not be empty"
            )
        for j, op in enumerate(ops_raw):
            if not isinstance(op, str):
                raise ConfigurationError(
                    f"permissions[{index}].allowed_operations[{j}] must be a "
                    f"string, got {type(op).__name__}"
                )
            if op not in VALID_OPERATIONS:
                raise ConfigurationError(
                    f"permissions[{index}].allowed_operations[{j}] has invalid "
                    f"value '{op}'; must be one of {sorted(VALID_OPERATIONS)}"
                )

        return Permission(
            group_id=group_id,
            path=path,
            allowed_operations=list(ops_raw),
        )
