"""Capability composition gate; no unreviewed combination is considered safe."""
from nexora.governance.interaction_matrix import InteractionMatrix


def validate_composition(capability_ids: list[int], matrix: InteractionMatrix) -> dict:
    if not isinstance(capability_ids, list) or len(capability_ids) < 2:
        raise ValueError("composition_requires_two_or_more_capabilities")
    checks = []
    for index, source in enumerate(capability_ids):
        for target in capability_ids[index + 1:]:
            checks.append({"source": source, "target": target, **matrix.relation(source, target)})
    allowed = all(item["known"] for item in checks)
    return {"eligible_for_review": allowed, "decision": "REVIEW_REQUIRED" if allowed else "BLOCK_AND_ESCALATE", "checks": checks}
