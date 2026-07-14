from shared.models import AccessEvaluationRequest, AccessEvaluationResponse


def build_access_request(
    actor_id: str,
    session_id: str,
    resource_id: str,
    requested_action: str,
    current_risk_score: float,
) -> AccessEvaluationRequest:
    return AccessEvaluationRequest(
        actor_id=actor_id,
        session_id=session_id,
        resource_id=resource_id,
        requested_action=requested_action,
        current_risk_score=current_risk_score,
    )


def map_decision_to_keycloak_action(response: AccessEvaluationResponse) -> dict[str, str | list[str]]:
    return {
        "decision": response.decision.value,
        "obligations": response.obligations,
        "justification": response.justification,
    }
