def build_authorization_tuple(actor_id: str, relation: str, resource_id: str) -> dict[str, str]:
    return {
        "user": f"user:{actor_id}",
        "relation": relation,
        "object": f"resource:{resource_id}",
    }
