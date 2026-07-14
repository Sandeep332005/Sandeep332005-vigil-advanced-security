from analytics.risk_engine import score_event
from ingestion.schemas import NormalizedEvent
from shared.models import RiskScoreResponse

def score_risk(payload: NormalizedEvent) -> RiskScoreResponse:
    return score_event(payload)
