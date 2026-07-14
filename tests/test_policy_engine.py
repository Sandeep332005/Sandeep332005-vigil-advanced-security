import unittest

from decisioning.policy_engine import evaluate_access
from shared.models import AccessEvaluationRequest, Decision


class PolicyEngineTests(unittest.TestCase):
    def test_low_risk_allows_access(self) -> None:
        response = evaluate_access(
            AccessEvaluationRequest(
                actor_id="alice",
                session_id="s1",
                resource_id="resource-1",
                requested_action="read",
                current_risk_score=10,
                trust_decay_score=1.0,
                honeytoken_hit=False,
                behavioral_twin_deviation=0.0,
            )
        )
        self.assertEqual(response.decision, Decision.allow)

    def test_medium_risk_requires_step_up(self) -> None:
        response = evaluate_access(
            AccessEvaluationRequest(
                actor_id="bob",
                session_id="s2",
                resource_id="resource-2",
                requested_action="write",
                current_risk_score=40,
                trust_decay_score=1.0,
                honeytoken_hit=False,
                behavioral_twin_deviation=0.0,
            )
        )
        self.assertEqual(response.decision, Decision.step_up)


if __name__ == "__main__":
    unittest.main()
