import unittest
from datetime import datetime, timezone

from analytics.risk_engine import score_event
from shared.models import ActorType, Decision, NormalizedEvent


def build_event(**overrides):
    payload = {
        "event_id": "evt-1",
        "timestamp": datetime.now(timezone.utc),
        "actor_id": "admin-1",
        "actor_type": ActorType.admin,
        "session_id": "sess-1",
        "source_system": "wazuh",
        "asset_id": "dc-1",
        "asset_criticality": 5,
        "action": "privilege_escalation",
        "privilege_level": 5,
        "resource_id": "vault",
        "resource_sensitivity": 5,
        "auth_context": {"failed_attempts": 4, "after_hours": True},
        "network_context": {"new_location": True},
        "change_window_context": {"approved": False},
        "raw_event_ref": "wazuh://evt-1",
    }
    payload.update(overrides)
    return NormalizedEvent(**payload)


class RiskEngineTests(unittest.TestCase):
    def test_high_risk_event_is_blocked(self) -> None:
        response = score_event(build_event())
        self.assertEqual(response.recommended_action, Decision.block)

    def test_low_risk_event_is_allowed(self) -> None:
        response = score_event(
            build_event(
                asset_criticality=1,
                privilege_level=0,
                resource_sensitivity=1,
                action="read",
                auth_context={"failed_attempts": 0, "after_hours": False},
                network_context={"new_location": False},
                change_window_context={"approved": True},
            )
        )
        self.assertEqual(response.recommended_action, Decision.allow)


if __name__ == "__main__":
    unittest.main()
