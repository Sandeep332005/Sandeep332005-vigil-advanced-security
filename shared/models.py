from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class ActorType(str, Enum):
    employee = "employee"
    contractor = "contractor"
    vendor = "vendor"
    admin = "admin"
    service = "service"


class Decision(str, Enum):
    allow = "allow"
    step_up = "step_up"
    restrict = "restrict"
    block = "block"


@dataclass
class NormalizedEvent:
    event_id: str
    timestamp: datetime
    actor_id: str
    actor_type: ActorType
    session_id: str
    source_system: str
    asset_id: str
    asset_criticality: int
    action: str
    privilege_level: int
    resource_id: str
    resource_sensitivity: int
    raw_event_ref: str
    auth_context: dict[str, Any] = field(default_factory=dict)
    network_context: dict[str, Any] = field(default_factory=dict)
    change_window_context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.asset_criticality = int(self.asset_criticality)
        self.privilege_level = int(self.privilege_level)
        self.resource_sensitivity = int(self.resource_sensitivity)
        if not 1 <= self.asset_criticality <= 5:
            raise ValueError("asset_criticality must be between 1 and 5")
        if not 0 <= self.privilege_level <= 5:
            raise ValueError("privilege_level must be between 0 and 5")
        if not 1 <= self.resource_sensitivity <= 5:
            raise ValueError("resource_sensitivity must be between 1 and 5")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "NormalizedEvent":
        normalized = dict(payload)
        if isinstance(normalized.get("timestamp"), str):
            normalized["timestamp"] = datetime.fromisoformat(normalized["timestamp"])
        if isinstance(normalized.get("actor_type"), str):
            normalized["actor_type"] = ActorType(normalized["actor_type"])
        return cls(**normalized)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["timestamp"] = self.timestamp.isoformat()
        payload["actor_type"] = self.actor_type.value
        return payload


@dataclass
class RiskScoreResponse:
    user_risk_score: float
    session_risk_score: float
    reasons: list[str]
    recommended_action: Decision
    expires_at: datetime

    @staticmethod
    def build(
        user_risk_score: float,
        session_risk_score: float,
        reasons: list[str],
        recommended_action: Decision,
        ttl_minutes: int = 30,
    ) -> "RiskScoreResponse":
        return RiskScoreResponse(
            user_risk_score=user_risk_score,
            session_risk_score=session_risk_score,
            reasons=reasons,
            recommended_action=recommended_action,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_risk_score": self.user_risk_score,
            "session_risk_score": self.session_risk_score,
            "reasons": self.reasons,
            "recommended_action": self.recommended_action.value,
            "expires_at": self.expires_at.isoformat(),
        }


@dataclass
class AccessEvaluationRequest:
    actor_id: str
    session_id: str
    resource_id: str
    requested_action: str
    current_risk_score: float
    trust_decay_score: float = 1.0
    honeytoken_hit: bool = False
    behavioral_twin_deviation: float = 0.0

    def __post_init__(self) -> None:
        self.current_risk_score = float(self.current_risk_score)
        self.trust_decay_score = float(self.trust_decay_score)
        self.behavioral_twin_deviation = float(self.behavioral_twin_deviation)
        if not 0 <= self.current_risk_score <= 100:
            raise ValueError("current_risk_score must be between 0 and 100")
        if not 0 <= self.trust_decay_score <= 1:
            raise ValueError("trust_decay_score must be between 0 and 1")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AccessEvaluationRequest":
        return cls(**payload)


@dataclass
class AccessEvaluationResponse:
    decision: Decision
    obligations: list[str]
    justification: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "obligations": self.obligations,
            "justification": self.justification,
        }


@dataclass
class EvidenceSignRequest:
    artifact_id: str
    artifact_hash: str
    artifact_type: str
    classification: str
    signer: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "EvidenceSignRequest":
        return cls(**payload)


@dataclass
class EvidenceSignResponse:
    artifact_id: str
    signature_id: str
    classical_signature: str
    pq_signature: str
    verification_chain: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
