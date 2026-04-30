"""
Alert Layer — displays terminal alerts for unauthorized access events.

Requirements: 7.1, 7.2, 7.3
"""

import threading
import time

from user_group_access_control.models import AccessEvent, Group


class AlertLayer:
    """Displays a real-time terminal alert when unauthorized access is detected.

    Alerts are printed directly to the terminal with clear formatting.
    
    Rate limiting: Only one alert per user/path combination within
    a configurable cooldown period (default: 60 seconds).
    """

    def __init__(self, cooldown_seconds: float = 60.0) -> None:
        self._groups: list[Group] = []
        self._cooldown_seconds = cooldown_seconds
        self._recent_alerts: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------

    def set_groups(self, groups: list[Group]) -> None:
        """Provide the group list so that group display names can be resolved.

        If a ``group_id`` passed to ``show_alert`` is not found in this list,
        the ``group_id`` itself is used as the display name.
        """
        self._groups = list(groups)

    # ------------------------------------------------------------------
    # Core alert operation
    # ------------------------------------------------------------------

    def show_alert(self, event: AccessEvent, group_id: str) -> None:
        """Display a terminal alert for *event* (fire-and-forget).

        The alert is printed to the terminal immediately. Rate limiting ensures
        only one alert per user/path combination within the cooldown period.
        
        DELETE operations bypass rate limiting to ensure they're always visible.
        """
        # DELETE operations always show alerts (critical security events)
        if event.operation == "DELETE":
            group_name = self._resolve_group_name(group_id)
            self._print_alert(event, group_id, group_name)
            return
        
        # Check if we should rate-limit this alert
        alert_key = (event.username, event.path)
        current_time = time.time()
        
        with self._lock:
            last_alert_time = self._recent_alerts.get(alert_key)
            
            if last_alert_time is not None:
                time_since_last = current_time - last_alert_time
                if time_since_last < self._cooldown_seconds:
                    # Skip this alert - too soon since last one
                    return
            
            # Record this alert time
            self._recent_alerts[alert_key] = current_time
            
            # Clean up old entries (older than cooldown period)
            cutoff_time = current_time - self._cooldown_seconds
            self._recent_alerts = {
                k: v for k, v in self._recent_alerts.items() if v > cutoff_time
            }
        
        group_name = self._resolve_group_name(group_id)
        self._print_alert(event, group_id, group_name)

    def _print_alert(self, event: AccessEvent, group_id: str, group_name: str) -> None:
        """Print a formatted alert to the terminal with color highlighting."""
        timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        
        # ANSI color codes
        RED = '\033[91m'
        RESET = '\033[0m'
        
        # Extract just the filename/foldername from the full path
        import os
        item_name = os.path.basename(event.path) if event.path else event.path
        
        print("\n" + "=" * 80)
        print("  UNAUTHORIZED ACCESS DETECTED")
        print("=" * 80)
        print(f"Timestamp : {timestamp}")
        print(f"User      : {event.username}")
        print(f"Group     : {group_id} ({group_name})")
        print(f"Operation : {RED}{event.operation}{RESET}")
        print(f"Path      : {event.path}")
        print(f"Item      : {RED}{item_name}{RESET}")
        print("=" * 80)
        print("This event has been logged to the access log file.")
        print("=" * 80 + "\n")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_group_name(self, group_id: str) -> str:
        """Return the display name for *group_id*, or *group_id* if not found."""
        for group in self._groups:
            if group.id == group_id:
                return group.name
        return group_id
