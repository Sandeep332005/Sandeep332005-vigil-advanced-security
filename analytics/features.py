from shared.models import NormalizedEvent


def extract_features(event: NormalizedEvent) -> dict[str, float]:
    return {
        "asset_criticality": float(event.asset_criticality),
        "privilege_level": float(event.privilege_level),
        "resource_sensitivity": float(event.resource_sensitivity),
        "failed_attempts": float(event.auth_context.get("failed_attempts", 0)),
        "new_location": 1.0 if event.network_context.get("new_location") else 0.0,
        "after_hours": 1.0 if event.auth_context.get("after_hours") else 0.0,
        "outside_change_window": 1.0 if event.change_window_context.get("approved") is False else 0.0,
    }
