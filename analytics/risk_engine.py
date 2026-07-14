from analytics.features import extract_features
from detections.rules import evaluate_detection_indicators
from shared.models import Decision, NormalizedEvent, RiskScoreResponse


def _pick_action(score: float) -> Decision:
    if score >= 80:
        return Decision.block
    if score >= 60:
        return Decision.restrict
    if score >= 35:
        return Decision.step_up
    return Decision.allow


def score_event(event: NormalizedEvent) -> RiskScoreResponse:
    features = extract_features(event)
    indicators = evaluate_detection_indicators(event)

    score = (
        features["asset_criticality"] * 8
        + features["privilege_level"] * 10
        + features["resource_sensitivity"] * 7
        + features["failed_attempts"] * 6
        + features["new_location"] * 10
        + features["after_hours"] * 8
        + features["outside_change_window"] * 12
    )

    if "privilege_elevation_activity" in indicators:
        score += 10
    if "high_privilege_on_critical_asset" in indicators:
        score += 10
    if "repeated_failed_logins" in indicators:
        score += 8

    final_score = min(round(score, 2), 100.0)
    action = _pick_action(final_score)

    return RiskScoreResponse.build(
        user_risk_score=final_score,
        session_risk_score=final_score,
        reasons=indicators or ["baseline_activity"],
        recommended_action=action,
    )
