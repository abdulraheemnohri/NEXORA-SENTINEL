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



def analyze_revocation_impact(
    capability_id: int, matrix_path: Path = DEFAULT_MATRIX,
) -> dict[str, Any]:
    """Find only explicitly declared transitive dependents; never infer or mutate."""
    if type(capability_id) is not int or not (1 <= capability_id <= 264):
        raise GovernanceValidationError("capability_id_out_of_range")
    matrix = _read_object(matrix_path, "interaction_matrix")
    if matrix.get("dimensions") != [264, 264] or matrix.get("capability_id_range") != [1, 264]:
        raise GovernanceValidationError("interaction_matrix_dimensions_invalid")
    if matrix.get("default_relation") != "unknown" or matrix.get(
        "unknown_relation_policy"
    ) != "deny_or_require_human_review":
        raise GovernanceValidationError("unknown_relation_policy_must_fail_closed")
    entries = matrix.get("entries")
    if not isinstance(entries, list):
        raise GovernanceValidationError("interaction_matrix_entries_must_be_list")
    seen: set[tuple[int, int]] = set()
    dependents: dict[int, set[int]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise GovernanceValidationError("interaction_matrix_entry_invalid")
        source, target, relation = entry.get("source"), entry.get("target"), entry.get("relation")
        if type(source) is not int or type(target) is not int or not (
            1 <= source <= 264 and 1 <= target <= 264
        ):
            raise GovernanceValidationError("interaction_matrix_pair_out_of_range")
        pair = (source, target)
        if pair in seen:
            raise GovernanceValidationError("interaction_matrix_duplicate_pair")
        seen.add(pair)
        if relation not in RELATIONS:
            raise GovernanceValidationError("interaction_matrix_relation_invalid")
        if relation == "depends_on":
            dependents.setdefault(target, set()).add(source)

    impacted: set[int] = set()
    frontier = [capability_id]
    cycles: list[list[int]] = []
    parent: dict[int, int] = {}
    while frontier:
        current = frontier.pop(0)
        for dependent in sorted(dependents.get(current, set())):
            if dependent == capability_id:
                node = current
                chain = [node]
                while node in parent and node != capability_id:
                    node = parent[node]
                    chain.append(node)
                cycles.append(list(reversed(chain)) + [capability_id])
                continue
            if dependent not in impacted:
                impacted.add(dependent)
                parent.setdefault(dependent, current)
                frontier.append(dependent)

    return {
        "capability_id": capability_id,
        "declared_dependents": sorted(impacted),
        "declared_dependent_count": len(impacted),
        "cycles_detected": cycles,
        "matrix_declared_pairs": len(seen),
        "matrix_possible_pairs": 264 * 264,
        "relationship_coverage_complete": len(seen) == 264 * 264,
        "decision": "HUMAN_REVIEW_REQUIRED",
        "unknown_relationships": "BLOCK_AND_ESCALATE",
        "automatic_dependent_revocation": False,
        "execution_enabled": False,
        "note": (
            "Only explicit directed depends_on edges are traversed. "
            "Undeclared relationships remain unknown; this report is not proof "
            "that the impact list is complete and does not revoke any capability."
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


def build_dependency_graph(matrix_path: Path = DEFAULT_MATRIX) -> dict[str, Any]:
    """Report only explicit directed depends_on edges and their graph cycles.

    Edge semantics: source capability depends on target capability. No inverse,
    family-derived, transitive, or inferred edge is ever materialized.
    """
    matrix = _read_object(matrix_path, "interaction_matrix")
    if matrix.get("dimensions") != [264, 264]:
        raise GovernanceValidationError("interaction_matrix_dimensions_invalid")
    if matrix.get("capability_id_range") != [1, 264]:
        raise GovernanceValidationError("interaction_matrix_id_range_invalid")
    if matrix.get("default_relation") != "unknown":
        raise GovernanceValidationError("default_relation_must_remain_unknown")
    if matrix.get("unknown_relation_policy") != "deny_or_require_human_review":
        raise GovernanceValidationError("unknown_relation_policy_must_fail_closed")
    allowed = matrix.get("allowed_relations")
    if (
        not isinstance(allowed, list)
        or len(allowed) != len(set(allowed))
        or set(allowed) != RELATIONS
    ):
        raise GovernanceValidationError("interaction_matrix_relation_vocabulary_invalid")
    entries = matrix.get("entries")
    if not isinstance(entries, list):
        raise GovernanceValidationError("interaction_matrix_entries_must_be_list")

    seen: set[tuple[int, int]] = set()
    adjacency: dict[int, set[int]] = {identifier: set() for identifier in range(1, 265)}
    relation_counts = {relation: 0 for relation in sorted(RELATIONS)}
    edges: list[dict[str, int]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise GovernanceValidationError("interaction_matrix_entry_invalid")
        source = entry.get("source")
        target = entry.get("target")
        relation = entry.get("relation")
        if (
            type(source) is not int
            or type(target) is not int
            or not (1 <= source <= 264 and 1 <= target <= 264)
        ):
            raise GovernanceValidationError("interaction_matrix_pair_out_of_range")
        pair = (source, target)
        if pair in seen:
            raise GovernanceValidationError("interaction_matrix_duplicate_pair")
        if relation not in RELATIONS:
            raise GovernanceValidationError("interaction_matrix_relation_invalid")
        seen.add(pair)
        relation_counts[relation] += 1
        if relation == "depends_on":
            adjacency[source].add(target)
            edges.append({"capability_id": source, "requires": target})

    # Tarjan strongly-connected components identify dependency cycles without
    # guessing their meaning or automatically resolving them.
    index = 0
    indexes: dict[int, int] = {}
    lowlinks: dict[int, int] = {}
    stack: list[int] = []
    on_stack: set[int] = set()
    components: list[list[int]] = []

    def visit(node: int) -> None:
        nonlocal index
        indexes[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for neighbor in sorted(adjacency[node]):
            if neighbor not in indexes:
                visit(neighbor)
                lowlinks[node] = min(lowlinks[node], lowlinks[neighbor])
            elif neighbor in on_stack:
                lowlinks[node] = min(lowlinks[node], indexes[neighbor])
        if lowlinks[node] == indexes[node]:
            component: list[int] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node:
                    break
            components.append(sorted(component))

    for node in range(1, 265):
        if node not in indexes:
            visit(node)

    cycles = [
        component for component in components
        if len(component) > 1
        or (len(component) == 1 and component[0] in adjacency[component[0]])
    ]
    cycles.sort(key=lambda component: component[0])
    possible_pairs = 264 * 264
    unknown_pairs = possible_pairs - len(seen)
    return {
        "status": "UNPOPULATED_BLOCKING" if not entries else "REVIEW_REQUIRED",
        "nodes": 264,
        "declared_relation_pairs": len(seen),
        "possible_relation_pairs": possible_pairs,
        "unknown_relation_pairs": unknown_pairs,
        "relationship_coverage_complete": unknown_pairs == 0,
        "relation_counts": relation_counts,
        "dependency_edge_count": len(edges),
        "dependency_edges": sorted(
            edges, key=lambda edge: (edge["capability_id"], edge["requires"])
        ),
        "dependency_cycles": cycles,
        "cycle_count": len(cycles),
        "unknown_relationship_decision": "BLOCK_AND_ESCALATE",
        "relationship_inference_enabled": False,
        "automatic_dependency_resolution": False,
        "execution_enabled": False,
        "read_only": True,
        "note": (
            "Only explicit directed depends_on entries are represented. "
            "Undeclared pairs stay unknown; cycles are reported, never repaired "
            "or resolved automatically."
        ),
    }
