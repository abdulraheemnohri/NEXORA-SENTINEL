from __future__ import annotations

import sqlite3

import pytest

from nexora.evidence import EvidenceError, EvidenceLedger
from nexora.evidence_provenance import build_provenance_report

HASH = "c" * 64


def test_provenance_declared_complete_partial_and_undeclared(tmp_path):
    path = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(path)
    ledger.add(
        85, "implementation_reference", "artifact://one", HASH, "operator",
        source_uri="https://github.com/example/project",
        source_revision="0123456789abcdef",
        collected_at="2026-11-19T10:00:00+05:00",
    )
    ledger.add(
        85, "test_report", "artifact://two", "d" * 64, "operator",
        source_uri="https://example.org/source",
    )
    ledger.add(86, "test_report", "artifact://three", "e" * 64, "operator")

    report = build_provenance_report(path)
    assert report["ledger_integrity"]["valid"] is True
    assert report["counts"] == {
        "DECLARED_COMPLETE": 1,
        "DECLARED_PARTIAL": 1,
        "UNDECLARED": 1,
        "UNVERIFIED": 0,
    }
    complete = report["records"][0]
    assert complete["source_revision"] == "0123456789abcdef"
    assert complete["collected_at"] == "2026-11-19T05:00:00.000000Z"


def test_provenance_is_capability_filterable_and_read_only(tmp_path):
    path = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(path)
    ledger.add(85, "implementation_reference", "ref", HASH, "operator",
               source_uri="https://example.org", source_revision="rev-1")
    report = build_provenance_report(path, capability_id=86)
    assert report["records"] == []
    assert report["complete"] is True
    with sqlite3.connect(path) as db:
        before = db.execute("SELECT record_hash FROM capability_evidence").fetchall()
    build_provenance_report(path)
    with sqlite3.connect(path) as db:
        after = db.execute("SELECT record_hash FROM capability_evidence").fetchall()
    assert before == after


@pytest.mark.parametrize("kwargs", [
    {"source_uri": ""},
    {"source_revision": " "},
    {"source_uri": "bad\nuri"},
    {"collected_at": "2026-11-19T10:00:00"},
])
def test_provenance_rejects_invalid_declarations(tmp_path, kwargs):
    ledger = EvidenceLedger(tmp_path / "registry.sqlite3")
    with pytest.raises(EvidenceError):
        ledger.add(85, "implementation_reference", "ref", HASH, "operator", **kwargs)


def test_provenance_integrity_failure_overrides_declared_status(tmp_path):
    path = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(path)
    ledger.add(85, "implementation_reference", "ref", HASH, "operator",
               source_uri="https://example.org", source_revision="rev-1")
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER capability_evidence_no_update")
        db.execute("UPDATE capability_evidence SET source_revision='tampered'")
    report = build_provenance_report(path)
    assert report["counts"]["UNVERIFIED"] == 1
    assert report["counts"]["DECLARED_COMPLETE"] == 0


def test_provenance_does_not_create_missing_database(tmp_path):
    path = tmp_path / "missing.sqlite3"
    with pytest.raises(EvidenceError, match="evidence_ledger_not_found"):
        build_provenance_report(path)
    assert not path.exists()


def test_cli_evidence_provenance_report(tmp_path, capsys):
    from nexora.cli import main

    args = [
        "--data-dir", str(tmp_path), "evidence", "add", "85",
        "--type", "implementation_reference", "--reference", "git:abc",
        "--sha256", HASH, "--operator", "operator",
        "--source-uri", "https://github.com/example/project",
        "--source-revision", "0123456789abcdef",
        "--collected-at", "2026-11-19T10:00:00+05:00", "--confirm",
    ]
    assert main(args) == 0
    capsys.readouterr()
    assert main(["--data-dir", str(tmp_path), "evidence", "provenance"]) == 0
    report = __import__("json").loads(capsys.readouterr().out)
    assert report["counts"]["DECLARED_COMPLETE"] == 1
