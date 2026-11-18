import json

import pytest

from nexora.governance.validation import (
    GovernanceValidationError,
    build_governance_report,
    inspect_relation,
)


def _artifacts(tmp_path, entries=None):
    matrix = {
        "schema_version": "1.1",
        "dimensions": [264, 264],
        "capability_id_range": [1, 264],
        "status": "unpopulated" if not entries else "partial",
        "default_relation": "unknown",
        "unknown_relation_policy": "deny_or_require_human_review",
        "allowed_relations": [
            "reinforces", "conflicts", "subsumes", "depends_on",
            "composes_with", "preempts",
        ],
        "entries": entries or [],
    }
    precedence = {
        "schema_version": 1,
        "priority_order": ["SAFETY", "GOVERNANCE", "OPERATIONAL", "CONVENIENCE"],
        "unknown_conflict": "BLOCK_AND_ESCALATE",
        "equal_priority_conflict": "BLOCK_AND_ESCALATE",
        "mutable_by_agent": False,
    }
    matrix_path, precedence_path = tmp_path / "matrix.json", tmp_path / "precedence.json"
    matrix_path.write_text(json.dumps(matrix), encoding="utf-8")
    precedence_path.write_text(json.dumps(precedence), encoding="utf-8")
    return matrix_path, precedence_path


def test_empty_matrix_is_valid_but_explicitly_blocking(tmp_path):
    matrix, precedence = _artifacts(tmp_path)
    report = build_governance_report(matrix, precedence)
    assert report["valid"] is True
    assert report["status"] == "UNPOPULATED_BLOCKING"
    assert report["matrix"]["unknown_pairs"] == 264 * 264
    assert report["controls"]["execution_enabled"] is False


def test_declared_directed_relationship_is_review_only(tmp_path):
    entry = {"source": 85, "target": 86, "relation": "depends_on"}
    matrix, precedence = _artifacts(tmp_path, [entry])
    report = build_governance_report(matrix, precedence)
    assert report["status"] == "DECLARED_RELATIONS_REVIEW_REQUIRED"
    assert report["matrix"]["relation_counts"]["depends_on"] == 1
    assert inspect_relation(85, 86, matrix)["decision"] == "REVIEW_REQUIRED"
    assert inspect_relation(86, 85, matrix)["decision"] == "BLOCK_AND_ESCALATE"


@pytest.mark.parametrize("mutation, message", [
    (lambda m, p: m.update(dimensions=[264, 263]), "dimensions_invalid"),
    (lambda m, p: m.update(default_relation="composes_with"), "default_relation_must_remain_unknown"),
    (lambda m, p: p.update(mutable_by_agent=True), "agent_precedence_mutation_forbidden"),
    (lambda m, p: p.update(unknown_conflict="ALLOW"), "unknown_conflict_must_block"),
])
def test_invalid_governance_contract_fails_closed(tmp_path, mutation, message):
    matrix, precedence = _artifacts(tmp_path)
    m, p = json.loads(matrix.read_text()), json.loads(precedence.read_text())
    mutation(m, p)
    matrix.write_text(json.dumps(m), encoding="utf-8")
    precedence.write_text(json.dumps(p), encoding="utf-8")
    with pytest.raises(GovernanceValidationError, match=message):
        build_governance_report(matrix, precedence)


def test_duplicate_pair_and_unknown_relation_are_rejected(tmp_path):
    entry = {"source": 1, "target": 2, "relation": "conflicts"}
    matrix, precedence = _artifacts(tmp_path, [entry, entry])
    with pytest.raises(GovernanceValidationError, match="duplicate_pair"):
        build_governance_report(matrix, precedence)
    m = json.loads(matrix.read_text())
    m["entries"] = [{"source": 1, "target": 2, "relation": "safe"}]
    matrix.write_text(json.dumps(m), encoding="utf-8")
    with pytest.raises(GovernanceValidationError, match="relation_invalid"):
        build_governance_report(matrix, precedence)


def test_relation_inspection_rejects_invalid_ids(tmp_path):
    matrix, _ = _artifacts(tmp_path)
    with pytest.raises(GovernanceValidationError, match="capability_id_out_of_range"):
        inspect_relation(0, 2, matrix)
