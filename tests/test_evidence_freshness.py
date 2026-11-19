from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
import pytest

from nexora.evidence import EvidenceError, EvidenceLedger
from nexora.evidence_freshness import build_freshness_report

HASH = "a" * 64


def test_legacy_and_unspecified_expiry_are_unknown(tmp_path):
    path = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(path)
    ledger.add(85, "implementation_reference", "git:abc", HASH, "operator")
    report = build_freshness_report(path)
    assert report["counts"]["UNKNOWN"] == 1
    assert report["records"][0]["status"] == "UNKNOWN"
    assert report["records"][0]["expires_at"] is None
    assert report["read_only"] is True


def test_operator_expiry_current_and_expired_boundary(tmp_path):
    path = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(path)
    ledger.add(
        85, "test_report", "artifact:test", HASH, "operator",
        expires_at="2026-11-19T12:00:00+05:00",
    )
    before = build_freshness_report(
        path, now=datetime(2026, 11, 19, 6, 59, 59, tzinfo=UTC),
    )
    at_boundary = build_freshness_report(
        path, now=datetime(2026, 11, 19, 7, 0, 0, tzinfo=UTC),
    )
    after = build_freshness_report(
        path, now=datetime(2026, 11, 19, 7, 0, 1, tzinfo=UTC),
    )
    assert before["counts"]["CURRENT"] == 1
    assert at_boundary["counts"]["CURRENT"] == 1
    assert after["counts"]["EXPIRED"] == 1


@pytest.mark.parametrize("value", [
    "2026-11-19T12:00:00",
    "not-a-date",
    "",
])
def test_expiry_requires_timezone_aware_iso8601(tmp_path, value):
    ledger = EvidenceLedger(tmp_path / "registry.sqlite3")
    with pytest.raises(EvidenceError, match="expires_at"):
        ledger.add(85, "test_report", "ref", HASH, "operator", expires_at=value)


def test_freshness_filter_and_report_limit_are_explicit(tmp_path):
    path = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(path)
    for i in range(3):
        ledger.add(85, "test_report", f"ref-{i}", f"{i + 1:064x}", "operator")
    report = build_freshness_report(path, capability_id=85)
    assert report["total_records"] == 3
    assert report["reported_records"] == 3
    assert report["complete"] is True
    assert report["counts"]["UNKNOWN"] == 3
    with pytest.raises(EvidenceError, match="capability_id_out_of_range"):
        build_freshness_report(path, capability_id=0)


def test_freshness_marks_all_records_unverified_when_chain_is_tampered(tmp_path):
    path = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(path)
    ledger.add(85, "test_report", "ref", HASH, "operator",
               expires_at="2027-01-01T00:00:00Z")
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER capability_evidence_no_update")
        db.execute("UPDATE capability_evidence SET expires_at='2020-01-01T00:00:00Z'")
    report = build_freshness_report(path, now=datetime(2026, 1, 1, tzinfo=UTC))
    assert report["ledger_integrity"]["valid"] is False
    assert report["counts"]["UNVERIFIED"] == 1
    assert report["counts"]["EXPIRED"] == 0


def test_freshness_does_not_create_missing_database(tmp_path):
    path = tmp_path / "missing.sqlite3"
    with pytest.raises(EvidenceError, match="evidence_ledger_not_found"):
        build_freshness_report(path)
    assert not path.exists()


def test_cli_add_and_freshness_commands(tmp_path, capsys):
    from nexora.cli import main

    args = [
        "--data-dir", str(tmp_path), "evidence", "add", "85",
        "--type", "test_report", "--reference", "artifact://cli-test",
        "--sha256", HASH, "--operator", "cli-operator",
        "--expires-at", "2027-01-01T00:00:00Z", "--confirm",
    ]
    assert main(args) == 0
    recorded = __import__("json").loads(capsys.readouterr().out)
    assert recorded["recorded"] is True
    assert recorded["expires_at"] == "2027-01-01T00:00:00.000000Z"

    assert main(["--data-dir", str(tmp_path), "evidence", "freshness"]) == 0
    report = __import__("json").loads(capsys.readouterr().out)
    assert report["counts"]["CURRENT"] == 1
