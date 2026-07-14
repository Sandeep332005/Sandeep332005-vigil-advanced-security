from typing import Any, Optional

class HoneytokenRegistry:
    def __init__(self) -> None:
        self.decoys: dict[str, dict[str, Any]] = {}
        self.alerts: list[dict[str, Any]] = []

    def register_decoy(self, asset_id: str, metadata: dict[str, Any]) -> None:
        self.decoys[asset_id] = metadata

    def check_access(self, asset_id: str, actor_id: str) -> Optional[dict[str, Any]]:
        if asset_id in self.decoys:
            decoy_meta = self.decoys[asset_id]
            alert = {
                "hit": True,
                "asset_id": asset_id,
                "actor_id": actor_id,
                "severity": decoy_meta.get("severity", "critical"),
                "justification": f"Access to registered honeytoken decoy asset '{asset_id}' detected.",
                "description": decoy_meta.get("description", "Decoy resource")
            }
            self.alerts.append(alert)
            return alert
        return None

    def get_alerts(self) -> list[dict[str, Any]]:
        return list(self.alerts)


honeytoken_registry = HoneytokenRegistry()

# Seed default decoys
honeytoken_registry.register_decoy("vault:secret:admin_backup", {"severity": "critical", "description": "Decoy admin backup secret"})
honeytoken_registry.register_decoy("host:etc:shadow_bak", {"severity": "high", "description": "Decoy shadow backup file"})
honeytoken_registry.register_decoy("keycloak:client:admin_keys", {"severity": "critical", "description": "Decoy keycloak admin keys"})
