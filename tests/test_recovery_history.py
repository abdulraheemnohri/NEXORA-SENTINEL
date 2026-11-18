import json
import sqlite3
from pathlib import Path

import pytest

from nexora.backup import create_backup, generate_backup_signing_key
from nexora.oversight.witness import verify_witness_chain
from nexora.recovery_history import (
    RecoveryHistoryError,
    read_recovery_history,
    record_recovery_simulation,
)


def _database(path: Path) -> Path:
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE sample(value TEXT)")
        db.execute("INSERT INTO sample VALUES('safe')")
    return path


def _keys(root: Path, prefix: str):
    private, public = root / f"{prefix}-private.pem", root / f"{prefix}-public.pem"
    generate_backup_signing_key(private, public)
    return private, public


def test_simulation_is_persisted_witnessed_and_audited(tmp_path):
    backup_private, backup_public = _keys(tmp_path, "backup")
    witness_private, witness_public = _keys(tmp_path, "witness")
    backup = tmp_path / "backup.sqlite3"
    create_backup(_database(tmp_path / "source.sqlite3"), backup, signing_key=backup_private)
    history = tmp_path / "history.jsonl"
    receipts = tmp_path / "receipts.jsonl"
    audit = tmp_path / "audit.jsonl"

    result = record_recovery_simulation(
        backup, backup_trusted_key=backup_public,
        witness_private_key=witness_private, witness_receipt_log=receipts,
        history_log=history, audit_log=audit,
    )

    assert result["recorded"] is True
    assert result["event"]["status"] == "PASSED"
    assert result["event"]["temporary_output_removed"] is True
    assert result["event"]["live_database_touched"] is False
    assert result["audit_recorded"] is True
    report = read_recovery_history(history, receipts, trusted_witness_public_key=witness_public)
    assert report["valid"] is True
    assert report["record_count"] == 1
    assert report["events"][0]["simulation_id"] == result["event"]["simulation_id"]
    assert verify_witness_chain(receipts, witness_public)["count"] == 1


def test_history_excludes_unwitnessed_rows(tmp_path):
    witness_private, witness_public = _keys(tmp_path, "witness")
    history = tmp_path / "history.jsonl"
    receipts = tmp_path / "receipts.jsonl"
    event = {"schema_version": 1, "simulation_id": "untrusted", "timestamp": "2026-01-01T00:00:00+00:00"}
    import hashlib
    digest = hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    receipts.write_text("")
    history.write_text(json.dumps({"event": event, "event_hash": digest}) + "\n")
    report = read_recovery_history(history, receipts, trusted_witness_public_key=witness_public)
    assert report["record_count"] == 0
    assert report["unwitnessed_records_excluded"] is True


def test_history_tampering_fails_closed(tmp_path):
    _, witness_public = _keys(tmp_path, "witness")
    history = tmp_path / "history.jsonl"
    receipts = tmp_path / "receipts.jsonl"
    receipts.write_text("")
    history.write_text(json.dumps({"event": {"simulation_id": "x"}, "event_hash": "0" * 64}) + "\n")
    with pytest.raises(RecoveryHistoryError, match="history_record_integrity_invalid"):
        read_recovery_history(history, receipts, trusted_witness_public_key=witness_public)


def test_simulation_requires_valid_backup_and_never_records_failure(tmp_path):
    backup_private, backup_public = _keys(tmp_path, "backup")
    witness_private, _ = _keys(tmp_path, "witness")
    backup = tmp_path / "backup.sqlite3"
    create_backup(_database(tmp_path / "source.sqlite3"), backup, signing_key=backup_private)
    backup.write_bytes(backup.read_bytes() + b"tamper")
    with pytest.raises(RecoveryHistoryError):
        record_recovery_simulation(
            backup, backup_trusted_key=backup_public,
            witness_private_key=witness_private,
            witness_receipt_log=tmp_path / "receipts.jsonl",
            history_log=tmp_path / "history.jsonl",
        )
    assert not (tmp_path / "receipts.jsonl").exists()
    assert not (tmp_path / "history.jsonl").exists()


def test_history_limit_is_bounded(tmp_path):
    _, public = _keys(tmp_path, "witness")
    with pytest.raises(RecoveryHistoryError, match="history_limit_out_of_range"):
        read_recovery_history(tmp_path / "history.jsonl", tmp_path / "receipts.jsonl",
                              trusted_witness_public_key=public, limit=0)
