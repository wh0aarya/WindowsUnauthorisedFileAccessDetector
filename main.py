"""
main.py — System entry point for User Group Access Control.

Wires all 8 components together and starts the monitoring loop.

Usage:
    python main.py <config_file_path>

Must be run from an elevated (Administrator) command prompt.

Requirements: 9.1, 9.2, 9.3, 9.4
"""

import ctypes
import sys
import time

from user_group_access_control.alert_layer import AlertLayer
from user_group_access_control.audit_policy_manager import AuditPolicyManager
from user_group_access_control.configuration_manager import ConfigurationManager
from user_group_access_control.event_evaluator import EventEvaluator
from user_group_access_control.event_log_reader import EventLogReader
from user_group_access_control.exceptions import ConfigurationError
from user_group_access_control.logging_layer import LoggingLayer
from user_group_access_control.policy_manager import PolicyManager
from user_group_access_control.user_manager import UserManager


def _is_admin() -> bool:
    """Return True if the current process has administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def main() -> None:
    # ------------------------------------------------------------------
    # Requirement 9.1 — Administrator privilege check
    # ------------------------------------------------------------------
    if not _is_admin():
        print(
            "ERROR: This program must be run as Administrator.\n"
            "Please right-click your terminal and choose 'Run as administrator',\n"
            "then re-launch: python main.py <config_file_path>",
            file=sys.stderr,
        )
        sys.exit(1)

    # ------------------------------------------------------------------
    # Requirement 9.2 — Config file path from command-line argument
    # ------------------------------------------------------------------
    if len(sys.argv) < 2:
        print(
            "Usage: python main.py <config_file_path>\n"
            "Example: python main.py config.json",
            file=sys.stderr,
        )
        sys.exit(1)

    config_path = sys.argv[1]

    # ------------------------------------------------------------------
    # Requirement 9.3 — Load and validate configuration
    # ------------------------------------------------------------------
    config_manager = ConfigurationManager()
    try:
        config = config_manager.load_from_file(config_path)
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    # ------------------------------------------------------------------
    # Requirement 9.4 — Instantiate and wire all 8 components
    # ------------------------------------------------------------------

    # (a) UserManager
    user_manager = UserManager()
    user_manager.register_users(config.users)

    # (b) PolicyManager
    policy_manager = PolicyManager()
    policy_manager.register_groups(config.groups)
    policy_manager.register_permissions(config.permissions)

    # (c) AuditPolicyManager — enables OS-level auditing on watched paths
    audit_policy_manager = AuditPolicyManager()
    watched_paths = policy_manager.get_watched_paths()
    audit_policy_manager.enable_auditing(watched_paths)

    # (d) LoggingLayer
    logging_layer = LoggingLayer()
    logging_layer.set_log_file(config.log_file_path)
    logging_layer.set_groups(config.groups)

    # (e) AlertLayer
    alert_layer = AlertLayer()
    alert_layer.set_groups(config.groups)

    # (f) EventEvaluator
    evaluator = EventEvaluator(
        user_manager=user_manager,
        policy_manager=policy_manager,
        alert_layer=alert_layer,
        logging_layer=logging_layer,
    )

    # (g) EventLogReader
    event_log_reader = EventLogReader()
    event_log_reader.set_log_file_path(config.log_file_path)

    # (h) Start polling
    event_log_reader.start_polling(watched_paths, evaluator.handle)

    # ------------------------------------------------------------------
    # Startup message
    # ------------------------------------------------------------------
    print("User Group Access Control — monitoring started.")
    print(f"Log file : {config.log_file_path}")
    print("Watching paths:")
    for path in watched_paths:
        print(f"  • {path}")
    print("Press Ctrl+C to stop.\n")

    # ------------------------------------------------------------------
    # Block until KeyboardInterrupt
    # ------------------------------------------------------------------
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down…")
        event_log_reader.stop()
        print("User Group Access Control stopped. Goodbye.")
        sys.exit(0)


if __name__ == "__main__":
    main()
