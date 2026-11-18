"""Read-only validation for source-backed capability governance artifacts.

No pairwise compatibility is inferred. Missing relationships remain blocking.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MATRIX = ROOT / "spec" / "interaction_matrix.json"
DEFAULT_PRECEDENCE = ROOT / "data" / "governance" / "precedence.json"
RELATIONS = {
    "reinforces", "conflicts", "subsumes", "depends_on",
    "composes_with", "preempts",
}
EXPECTED_PRECEDENCE = ["safety", "governance", "all_other_capabilities"]


class GovernanceValidationError(ValueError):
    """A governance artifact is malformed or violates its fixed contract."""


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GovernanceValidationError(f"{label}_read_failed") from exc
    if not isinstance(payload, dict):
        raise GovernanceValidationError(f"{label}_must_be_object")
    return payload


def build_governance_report(
    matrix_path: Path = DEFAULT_MATRIX,
    precedence_path: Path = DEFAULT_PRECEDENCE,
) -> dict[str, Any]:
    """Validate declared governance data and report unknown relation coverage."""
    matrix = _read_object(matrix_path, "interaction_matrix")
    precedence = _read_object(precedence_path, "precedence")
    if matrix.get("dimensions") != [264, 264]:
        raise GovernanceValidationError("interaction_matrix_dimensions_invalid")
    if matrix.get("capability_id_range") != [1, 264]:
        raise GovernanceValidationError("interaction_matrix_id_range_invalid")
    if matrix.get("unknown_relation_policy") != "deny_or_require_human_review":
        raise GovernanceValidationError("unknown_relation_policy_must_fail_closed")
    if matrix.get("default_relation") != "unknown":
        raise GovernanceValidationError("default_relation_must_remain_unknown")
    allowed = matrix.get("allowed_relations")
    if not isinstance(allowed, list) or len(allowed) != len(set(allowed)) or set(allowed) != RELATIONS:
        raise GovernanceValidationError("interaction_matrix_relation_vocabulary_invalid")
    entries = matrix.get("entries")
    if not isinstance(entries, list):
        raise GovernanceValidationError("interaction_matrix_entries_must_be_list")
    seen: set[tuple[int, int]] = set()
    relation_counts = {relation: 0 for relation in sorted(RELATIONS)}
    for entry in entries:
        if not isinstance(entry, dict):
            raise GovernanceValidationError("interaction_matrix_entry_invalid")
        source, target, relation = entry.get("source"), entry.get("target"), entry.get("relation")
        if type(source) is not int or type(target) is not int or not (1 <= source <= 264 and 1 <= target <= 264):
            raise GovernanceValidationError("interaction_matrix_pair_out_of_range")
        pair = (source, target)
        if pair in seen:
            raise GovernanceValidationError("interaction_matrix_duplicate_pair")
        if relation not in RELATIONS:
            raise GovernanceValidationError("interaction_matrix_relation_invalid")
        seen.add(pair)
        relation_counts[relation] += 1

    if precedence.get("priority_order") != ["SAFETY", "GOVERNANCE", "OPERATIONAL", "CONVENIENCE"]:
        raise GovernanceValidationError("precedence_order_invalid")
    if precedence.get("unknown_conflict") != "BLOCK_AND_ESCALATE":
        raise GovernanceValidationError("unknown_conflict_must_block")
    if precedence.get("equal_priority_conflict") != "BLOCK_AND_ESCALATE":
        raise GovernanceValidationError("equal_priority_conflict_must_block")
    if precedence.get("mutable_by_agent") is not False:
        raise GovernanceValidationError("agent_precedence_mutation_forbidden")

    possible_pairs = 264 * 264
    unknown_pairs = possible_pairs - len(seen)
    return {
        "status": "UNPOPULATED_BLOCKING" if not entries else "DECLARED_RELATIONS_REVIEW_REQUIRED",
        "valid": True,
        "matrix": {
            "schema_version": matrix.get("schema_version"),
            "dimensions": [264, 264],
            "declared_pairs": len(seen),
            "possible_pairs": possible_pairs,
            "unknown_pairs": unknown_pairs,
            "coverage_ratio": round(len(seen) / possible_pairs, 8),
            "relation_counts": relation_counts,
            "unknown_relation_decision": "BLOCK_AND_ESCALATE",
            "automatic_compatibility_grants": False,
        },
        "precedence": {
            "priority_order": precedence["priority_order"],
            "unknown_conflict": precedence["unknown_conflict"],
            "equal_priority_conflict": precedence["equal_priority_conflict"],
            "mutable_by_agent": False,
            "valid": True,
        },
        "controls": {
            "read_only": True,
            "execution_enabled": False,
            "policy_mutation_enabled": False,
            "relationship_inference_enabled": False,
            "human_review_required_for_declared_relations": True,
        },
        "note": (
            "A declared relationship is evidence for review, not an authorization. "
            "Missing pairs remain BLOCK_AND_ESCALATE; no symmetry or transitive "
            "relationship is inferred."
        ),
    }


def inspect_relation(source: int, target: int, matrix_path: Path = DEFAULT_MATRIX) -> dict[str, Any]:
    """Return one directed pair exactly as declared; never infer reverse edges."""
    if type(source) is not int or type(target) is not int or not (1 <= source <= 264 and 1 <= target <= 264):
        raise GovernanceValidationError("capability_id_out_of_range")
    matrix = _read_object(matrix_path, "interaction_matrix")
    entries = matrix.get("entries")
    if not isinstance(entries, list):
        raise GovernanceValidationError("interaction_matrix_entries_must_be_list")
    matches = [row for row in entries if isinstance(row, dict)
               and row.get("source") == source and row.get("target") == target]
    if len(matches) > 1:
        raise GovernanceValidationError("interaction_matrix_duplicate_pair")
    if not matches:
        return {"source": source, "target": target, "known": False,
                "decision": "BLOCK_AND_ESCALATE"}
    return {"source": source, "target": target, "known": True,
            "decision": "REVIEW_REQUIRED", "entry": matches[0]}
