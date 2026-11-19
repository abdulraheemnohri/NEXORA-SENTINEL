import json

import pytest

from nexora.governance.validation import (
    GovernanceValidationError,
    build_dependency_graph,
)


def _matrix(path, entries):
    path.write_text(json.dumps({
        "schema_version": "1.1",
        "dimensions": [264, 264],
        "capability_id_range": [1, 264],
        "status": "partial" if entries else "unpopulated",
        "default_relation": "unknown",
        "unknown_relation_policy": "deny_or_require_human_review",
        "allowed_relations": [
            "reinforces", "conflicts", "subsumes", "depends_on",
            "composes_with", "preempts",
        ],
        "entries": entries,
    }), encoding="utf-8")


def test_dependency_graph_contains_only_explicit_directed_edges(tmp_path):
    matrix = tmp_path / "matrix.json"
    _matrix(matrix, [
        {"source": 20, "target": 10, "relation": "depends_on"},
        {"source": 30, "target": 20, "relation": "depends_on"},
        {"source": 40, "target": 10, "relation": "conflicts"},
    ])

    report = build_dependency_graph(matrix)

    assert report["dependency_edges"] == [
        {"capability_id": 20, "requires": 10},
        {"capability_id": 30, "requires": 20},
    ]
    assert report["dependency_edge_count"] == 2
    assert report["unknown_relation_pairs"] == 264 * 264 - 3
    assert report["relationship_inference_enabled"] is False
    assert report["automatic_dependency_resolution"] is False
    assert report["execution_enabled"] is False
    assert not any(
        edge == {"capability_id": 10, "requires": 20}
        for edge in report["dependency_edges"]
    )


def test_dependency_graph_reports_cycle_without_resolving_it(tmp_path):
    matrix = tmp_path / "matrix.json"
    _matrix(matrix, [
        {"source": 10, "target": 20, "relation": "depends_on"},
        {"source": 20, "target": 10, "relation": "depends_on"},
        {"source": 30, "target": 30, "relation": "depends_on"},
    ])

    report = build_dependency_graph(matrix)

    assert report["dependency_cycles"] == [[10, 20], [30]]
    assert report["cycle_count"] == 2
    assert report["automatic_dependency_resolution"] is False


def test_dependency_graph_empty_matrix_is_blocking(tmp_path):
    matrix = tmp_path / "matrix.json"
    _matrix(matrix, [])

    report = build_dependency_graph(matrix)

    assert report["status"] == "UNPOPULATED_BLOCKING"
    assert report["dependency_edges"] == []
    assert report["unknown_relation_pairs"] == 264 * 264


def test_dependency_graph_rejects_duplicate_pairs(tmp_path):
    matrix = tmp_path / "matrix.json"
    entry = {"source": 1, "target": 2, "relation": "depends_on"}
    _matrix(matrix, [entry, entry])

    with pytest.raises(GovernanceValidationError, match="duplicate_pair"):
        build_dependency_graph(matrix)
