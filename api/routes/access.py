from decisioning.policy_engine import evaluate_access
from shared.models import AccessEvaluationRequest, AccessEvaluationResponse

def evaluate(payload: AccessEvaluationRequest) -> AccessEvaluationResponse:
    return evaluate_access(payload)
