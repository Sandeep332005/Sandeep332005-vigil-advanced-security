import time
import uuid
from typing import Any

class KeyRotationPolicy:
    def __init__(
        self,
        rotation_interval_sec: float = 300.0,
        max_usage_count: int = 50,
        trust_threshold: float = 0.4,
    ) -> None:
        self.rotation_interval_sec = rotation_interval_sec
        self.max_usage_count = max_usage_count
        self.trust_threshold = trust_threshold
        self.keys: dict[str, dict[str, Any]] = {}

    def get_key_metadata(self, actor_id: str) -> dict[str, Any]:
        if actor_id not in self.keys:
            self.rotate_key(actor_id)
        return self.keys[actor_id]

    def record_usage(self, actor_id: str) -> None:
        meta = self.get_key_metadata(actor_id)
        meta["usage_count"] += 1

    def rotate_key(self, actor_id: str) -> dict[str, Any]:
        meta = {
            "key_id": f"qpc-key-{uuid.uuid4().hex[:8]}",
            "created_at": time.time(),
            "usage_count": 0,
            "algorithm": "hybrid-ecdsa-dilithium5",
            "compliance_status": "compliant"
        }
        self.keys[actor_id] = meta
        return meta

    def rotate(self, actor_id: str) -> dict[str, Any]:
        return self.rotate_key(actor_id)

    def should_rotate(self, actor_id: str, trust_score: float) -> bool:
        if actor_id not in self.keys:
            return True
        rotation_eval = self.evaluate_rotation(actor_id)
        return (
            trust_score <= self.trust_threshold
            or rotation_eval["mandatory_rotation"]
            or rotation_eval["recommend_rotation"]
        )

    def evaluate_rotation(self, actor_id: str) -> dict[str, Any]:
        meta = self.get_key_metadata(actor_id)
        age = time.time() - meta["created_at"]
        usage = meta["usage_count"]
        
        recommend_rotation = False
        mandatory_rotation = False
        reasons = []

        if age >= self.rotation_interval_sec:
            recommend_rotation = True
            mandatory_rotation = True
            reasons.append("rotation_interval_elapsed")
            
        if usage >= self.max_usage_count:
            recommend_rotation = True
            mandatory_rotation = True
            reasons.append("max_usage_limit_exceeded")
            
        if not mandatory_rotation:
            if age >= self.rotation_interval_sec * 0.8:
                recommend_rotation = True
                reasons.append("rotation_interval_warning")
            if usage >= self.max_usage_count * 0.8:
                recommend_rotation = True
                reasons.append("usage_count_warning")

        status = "compliant"
        if mandatory_rotation:
            status = "non_compliant_rotation_required"

        return {
            "actor_id": actor_id,
            "key_id": meta["key_id"],
            "age_seconds": round(age, 2),
            "usage_count": usage,
            "recommend_rotation": recommend_rotation,
            "mandatory_rotation": mandatory_rotation,
            "reasons": reasons,
            "compliance_status": status
        }
