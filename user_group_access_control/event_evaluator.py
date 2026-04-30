"""
Event Evaluator — orchestrates group resolution, policy checks, alerting, and logging.

Requirements: 6.1, 6.2, 6.3, 6.4
"""

from user_group_access_control.alert_layer import AlertLayer
from user_group_access_control.logging_layer import LoggingLayer
from user_group_access_control.models import AccessEvent
from user_group_access_control.policy_manager import PolicyManager
from user_group_access_control.user_manager import UserManager

_UNKNOWN_GROUP = "UNKNOWN_GROUP"


class EventEvaluator:
    """Evaluates each ``AccessEvent`` against the configured policy.

    For every event:
    1. Resolve the user's group via ``UserManager``; fall back to
       ``"UNKNOWN_GROUP"`` when the username is not registered.
    2. Ask ``PolicyManager`` whether the group is authorized for the
       requested operation on the accessed path.
    3. If **not** authorized: fire both ``AlertLayer.show_alert`` and
       ``LoggingLayer.write_log`` — neither may be skipped.
    4. If authorized: no side effects.
    """

    def __init__(
        self,
        user_manager: UserManager,
        policy_manager: PolicyManager,
        alert_layer: AlertLayer,
        logging_layer: LoggingLayer,
    ) -> None:
        self._user_manager = user_manager
        self._policy_manager = policy_manager
        self._alert_layer = alert_layer
        self._logging_layer = logging_layer

    def handle(self, event: AccessEvent) -> None:
        """Evaluate *event* and trigger alerts/logging when access is unauthorized.

        Args:
            event: The ``AccessEvent`` to evaluate.
        """
        # Step 1: resolve group, fall back to UNKNOWN_GROUP
        group_id: str = self._user_manager.resolve_group(event.username) or _UNKNOWN_GROUP

        # Step 2: check authorization
        authorized: bool = self._policy_manager.is_authorized(
            group_id, event.path, event.operation
        )

        # Step 3: unauthorized → alert AND log (both are mandatory)
        if not authorized:
            self._alert_layer.show_alert(event, group_id)
            self._logging_layer.write_log(event, group_id)
        # Step 4: authorized → no side effects
