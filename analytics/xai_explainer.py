from typing import Any

class RiskExplainer:
    def explain(self, features: dict[str, float], indicators: list[str], risk_score: float) -> dict[str, Any]:
        weights = {
            "asset_criticality": 8.0,
            "privilege_level": 10.0,
            "resource_sensitivity": 7.0,
            "failed_attempts": 6.0,
            "new_location": 10.0,
            "after_hours": 8.0,
            "outside_change_window": 12.0,
            "privilege_elevation_activity": 10.0,
            "high_privilege_on_critical_asset": 10.0,
            "repeated_failed_logins": 8.0,
            "behavioral_twin_dev": 25.0,
            "honeytoken_breach": 100.0
        }

        contributions = {}
        total = 0.0

        for key, weight in weights.items():
            if key in features:
                val = features[key]
                contrib = val * weight
                if contrib > 0:
                    contributions[key] = contrib
                    total += contrib
            elif key in indicators:
                contributions[key] = weight
                total += weight

        if "honeytoken_breach" in indicators:
            contributions = {"honeytoken_breach": 100.0}
            total = 100.0

        factors = []
        if total > 0:
            for factor, val in contributions.items():
                pct = (val / total) * 100.0
                factors.append({
                    "factor": factor,
                    "contribution": round(val, 2),
                    "percentage": round(pct, 2),
                    "description": self._get_factor_description(factor)
                })
        else:
            factors.append({
                "factor": "baseline",
                "contribution": 0.0,
                "percentage": 100.0,
                "description": "Baseline user behavior patterns."
            })

        factors.sort(key=lambda x: x["contribution"], reverse=True)

        is_anomalous = risk_score >= 35.0
        justification = (
            f"Anomalous event detected with risk score of {risk_score:.1f}. "
            f"Primary driver: {factors[0]['factor']} ({factors[0]['percentage']:.1f}%)."
            if is_anomalous else
            f"Normal baseline event with risk score of {risk_score:.1f}."
        )

        return {
            "risk_score": risk_score,
            "is_anomalous": is_anomalous,
            "factors": factors,
            "justification": justification
        }

    def _get_factor_description(self, factor: str) -> str:
        descriptions = {
            "asset_criticality": "Access to high-criticality enterprise assets.",
            "privilege_level": "Operations requiring elevated privilege levels.",
            "resource_sensitivity": "Reading/writing to highly sensitive resources.",
            "failed_attempts": "Multiple failed authentication attempts detected.",
            "new_location": "Access initiated from an unusual network location.",
            "after_hours": "Activity outside standard business working hours.",
            "outside_change_window": "Unscheduled operation outside approved change window.",
            "privilege_elevation_activity": "Active attempt to escalate privileges (sudo/admin).",
            "high_privilege_on_critical_asset": "Elevated admin credentials active on critical asset.",
            "repeated_failed_logins": "Sequential authentication failures observed.",
            "behavioral_twin_dev": "Action deviates significantly from predicted digital twin sequence.",
            "honeytoken_breach": "Decoy honeytoken triggered. Confirmed intrusion signature.",
        }
        return descriptions.get(factor, "Unknown contributing factor.")
