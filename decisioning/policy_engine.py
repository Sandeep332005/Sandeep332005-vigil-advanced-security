from datetime import datetime, timezone
from shared.models import AccessEvaluationRequest, AccessEvaluationResponse, Decision

class TrustSession:
    def __init__(self, session_id: str, base_trust: float = 1.0, decay_rate_per_minute: float = 0.05) -> None:
        self.session_id = session_id
        self.base_trust = base_trust
        self.decay_rate_per_minute = decay_rate_per_minute
        self.last_activity_at = datetime.now(timezone.utc)
        self.suspicious_multiplier = 1.0

    def current_trust(self, now: datetime = None) -> float:
        if now is None:
            now = datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        if self.last_activity_at.tzinfo is None:
            self.last_activity_at = self.last_activity_at.replace(tzinfo=timezone.utc)
            
        elapsed = (now - self.last_activity_at).total_seconds() / 60.0
        decay = self.decay_rate_per_minute * elapsed * self.suspicious_multiplier
        return max(0.0, self.base_trust - decay)

    def record_activity(self, is_suspicious: bool = False, now: datetime = None) -> None:
        if now is None:
            now = datetime.now(timezone.utc)
        self.last_activity_at = now
        if is_suspicious:
            self.suspicious_multiplier += 0.5
        else:
            self.suspicious_multiplier = max(1.0, self.suspicious_multiplier - 0.1)


def evaluate_access(payload: AccessEvaluationRequest) -> AccessEvaluationResponse:
    if payload.honeytoken_hit:
        return AccessEvaluationResponse(
            decision=Decision.block,
            obligations=["terminate_session", "revoke_credentials", "open_incident", "notify_soc"],
            justification="Critical honeytoken decoy asset breach detected. Access blocked.",
        )
        
    # Evaluate risk score, trust decay score, and behavioral deviation
    if payload.current_risk_score >= 80 or payload.trust_decay_score < 0.2:
        return AccessEvaluationResponse(
            decision=Decision.block,
            obligations=["terminate_session", "open_incident", "notify_soc"],
            justification=f"Critical risk (score={payload.current_risk_score:.1f}) or depleted trust (score={payload.trust_decay_score:.2f}) requires immediate blocking.",
        )
        
    if payload.current_risk_score >= 60 or payload.trust_decay_score < 0.5 or payload.behavioral_twin_deviation >= 0.8:
        return AccessEvaluationResponse(
            decision=Decision.restrict,
            obligations=["restrict_privileged_actions", "step_up_mfa", "notify_manager"],
            justification=f"High risk score, trust degradation, or high digital twin deviation ({payload.behavioral_twin_deviation:.2f}) requires restricted access.",
        )
        
    if payload.current_risk_score >= 35 or payload.trust_decay_score < 0.8 or payload.behavioral_twin_deviation >= 0.4:
        return AccessEvaluationResponse(
            decision=Decision.step_up,
            obligations=["require_mfa", "record_reason_code"],
            justification="Medium risk parameters or declining trust require step-up authentication.",
        )
        
    return AccessEvaluationResponse(
        decision=Decision.allow,
        obligations=["log_access_decision"],
        justification="All security metrics are within acceptable baseline parameters.",
    )
