import json

import pytest

from nexora.governance.arbitration import (
    ArbitrationError,
    arbitrate_conflict,
    load_wait_graph,
)


def _matrix(tmp_path, relation="conflicts"):
    path = tmp_path / "matrix.json"
    path.write_text(json.dumps({
        "dimensions": [264, 264],
        "entries": [{"source": 85, "target": 86, "relation": relation}],
    }), encoding="utf-8")
    return path


def test_explicit_conflict_proposes_safety_winner_but_never_authorizes(tmp_path):
    report = arbitrate_conflict(
        85, 86, left_priority="SAFETY", right_priority="OPERATIONAL",
        matrix_path=_matrix(tmp_path),
    )
    assert report["decision"] == "PRECEDENCE_WINNER_PROPOSED_REVIEW_REQUIRED"
    assert report["winner_proposal"] == 85
    assert report["human_review_required"] is True
    assert report["proposal_authorized"] is False
    assert report["execution_enabled"] is False
    assert report["lifecycle_mutation"] is False


def test_unknown_relationship_blocks(tmp_path):
    report = arbitrate_conflict(
        85, 86, left_priority="SAFETY", right_priority="CONVENIENCE",
        matrix_path=_matrix(tmp_path, relation=None) if False else tmp_path / "empty.json",
    ) if False else None
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"dimensions": [264, 264], "entries": []}), encoding="utf-8")
    report = arbitrate_conflict(
        85, 86, left_priority="SAFETY", right_priority="CONVENIENCE",
        matrix_path=path,
    )
    assert report["decision"] == "BLOCK_AND_ESCALATE"
    assert report["reason"] == "relationship_unknown"
    assert report["winner_proposal"] is None


def test_non_conflict_relation_cannot_be_arbitrated(tmp_path):
    report = arbitrate_conflict(
        85, 86, left_priority="SAFETY", right_priority="CONVENIENCE",
        matrix_path=_matrix(tmp_path, "depends_on"),
    )
    assert report["decision"] == "BLOCK_AND_ESCALATE"
    assert report["reason"] == "explicit_conflicts_relation_required"


def test_equal_or_unknown_priority_blocks(tmp_path):
    path = _matrix(tmp_path)
    for left, right in [("SAFETY", "SAFETY"), ("UNKNOWN", "CONVENIENCE")]:
        report = arbitrate_conflict(
            85, 86, left_priority=left, right_priority=right, matrix_path=path,
        )
        assert report["decision"] == "BLOCK_AND_ESCALATE"
        assert report["winner_proposal"] is None


def test_deadlock_blocks_precedence_winner(tmp_path):
    report = arbitrate_conflict(
        85, 86, left_priority="SAFETY", right_priority="CONVENIENCE",
        matrix_path=_matrix(tmp_path),
        wait_graph={"proposal-85": ["proposal-86"], "proposal-86": ["proposal-85"]},
    )
    assert report["decision"] == "BLOCK_AND_ESCALATE"
    assert report["reason"] == "wait_graph_deadlock_detected"
    assert report["deadlock_detected"] is True
    assert report["winner_proposal"] is None


def test_unknown_wait_graph_node_blocks(tmp_path):
    report = arbitrate_conflict(
        85, 86, left_priority="SAFETY", right_priority="CONVENIENCE",
        matrix_path=_matrix(tmp_path),
        wait_graph={"proposal-85": ["missing-node"]},
    )
    assert report["decision"] == "BLOCK_AND_ESCALATE"
    assert report["reason"] == "wait_graph_unknown_node"


def test_invalid_wait_graph_fails_closed(tmp_path):
    with pytest.raises(ArbitrationError, match="wait_graph_invalid"):
        arbitrate_conflict(
            85, 86, left_priority="SAFETY", right_priority="CONVENIENCE",
            matrix_path=_matrix(tmp_path), wait_graph={"a": "b"},
        )


def test_wait_graph_loader_rejects_non_object(tmp_path):
    path = tmp_path / "graph.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ArbitrationError, match="wait_graph_must_be_object"):
        load_wait_graph(path)
