from datetime import datetime, timezone
from uuid import uuid4

from shared.models import ActorType, NormalizedEvent


def normalize_wazuh_event(event: dict) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event.get("event_id", str(uuid4())),
        timestamp=event.get("timestamp", datetime.now(timezone.utc)),
        actor_id=event["actor_id"],
        actor_type=ActorType(event.get("actor_type", "employee")),
        session_id=event.get("session_id", "unknown-session"),
        source_system=event.get("source_system", "wazuh"),
        asset_id=event.get("asset_id", "unknown-asset"),
        asset_criticality=event.get("asset_criticality", 3),
        action=event.get("action", "unknown"),
        privilege_level=event.get("privilege_level", 0),
        resource_id=event.get("resource_id", "unknown-resource"),
        resource_sensitivity=event.get("resource_sensitivity", 3),
        auth_context=event.get("auth_context", {}),
        network_context=event.get("network_context", {}),
        change_window_context=event.get("change_window_context", {}),
        raw_event_ref=event.get("raw_event_ref", "wazuh://unknown"),
    )
