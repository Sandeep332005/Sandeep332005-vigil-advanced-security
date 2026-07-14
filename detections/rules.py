from shared.models import NormalizedEvent


def evaluate_detection_indicators(event: NormalizedEvent) -> list[str]:
    indicators: list[str] = []

    if event.privilege_level >= 4 and event.asset_criticality >= 4:
        indicators.append("high_privilege_on_critical_asset")
    if event.action in {"privilege_escalation", "sudo", "role_assignment"}:
        indicators.append("privilege_elevation_activity")
    if event.resource_sensitivity >= 4:
        indicators.append("sensitive_resource_access")
    if event.network_context.get("new_location"):
        indicators.append("new_location")
    if event.auth_context.get("failed_attempts", 0) >= 3:
        indicators.append("repeated_failed_logins")
    if event.change_window_context.get("approved") is False:
        indicators.append("outside_change_window")

    return indicators
