from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

Operation = Literal["READ", "WRITE", "DELETE", "RENAME", "CREATE"]


@dataclass
class Group:
    id: str           # unique identifier (e.g. "admin")
    name: str         # display name (e.g. "Administrators")
    description: str = ""  # optional description


@dataclass
class UserRecord:
    username: str   # Windows OS username
    group_id: str   # references a Group.id


@dataclass
class Permission:
    group_id: str                      # references a Group.id
    path: str                          # absolute Windows path
    allowed_operations: list[Operation] = field(default_factory=list)


@dataclass
class AccessEvent:
    username: str         # Windows username from Security Event Log (SubjectUserName)
    path: str             # absolute path from Security Event Log (ObjectName)
    operation: Operation  # mapped from AccessMask bitmask
    timestamp: datetime   # TimeCreated from the event log entry


@dataclass
class Config:
    groups: list[Group] = field(default_factory=list)
    users: list[UserRecord] = field(default_factory=list)
    permissions: list[Permission] = field(default_factory=list)
    log_file_path: str = ""
