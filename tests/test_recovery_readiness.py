import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from nexora.backup import create_backup, generate_backup_signing_key
from nexora.recovery_readiness import (
    RecoveryReadinessError,
    RecoverySettings,
    build_recovery_readiness,
)


def _make_db(path: Path) -> Path:
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE sample(value TEXT)")
        db.execute("INSERT INTO sample VALUES('recovery')")
    return path


def test_settings_defaults_are_safe_and_validated():
    settings = RecoverySettings().validate()
    assert settings.automatic_restore is False
    assert settings.automatic_deletion is False
    assert settings.require_simulation_confirmation is True


def test_settings_reject_automatic_restore_and_unknown_fields(tmp_path):
    path = tmp_path / "recovery.json"
    path.write_text(json.dumps({"automatic_restore": True}))
    with pytest.raises(RecoveryReadinessError, match="automatic_recovery_actions_are_prohibited"):
        RecoverySettings.load(path)
    path.write_text(json.dumps({"unknown": True}))
    with pytest.raises(RecoveryReadinessError, match="recovery_settings_schema_invalid"):
        RecoverySettings.load(path)


def test_readiness_blocks_without_independent_trust_anchor(tmp_path):
    directory = tmp_path / "backups"
    directory.mkdir()
    report = build_recovery_readiness(directory, trusted_public_key=None)
    assert report["status"] == "BLOCKED_TRUST_ANCHOR"
    assert report["score"] == 0
    assert report["automatic_restore"] is False


def test_readiness_scores_fresh_verified_backup(tmp_path):
    directory = tmp_path / "backups"
    directory.mkdir()
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    generate_backup_signing_key(private, public)
    backup = directory / "daily.sqlite3"
    manifest = create_backup(_make_db(tmp_path / "source.sqlite3"), backup, signing_key=private)
    fixed = datetime.fromisoformat(manifest["created_at"]) + timedelta(minutes=1)
    report = build_recovery_readiness(
        directory, trusted_public_key=public, now=fixed,
        max_backup_age_hours=24, min_verified_points=1,
    )
    assert report["status"] == "READY"
    assert report["score"] == 100
    assert report["verified_recovery_points"] == 1
    assert report["recovery_simulation"] == "NOT_RECORDED"
    assert backup.exists()


def test_readiness_marks_stale_backup_degraded(tmp_path):
    directory = tmp_path / "backups"
    directory.mkdir()
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    generate_backup_signing_key(private, public)
    backup = directory / "old.sqlite3"
    manifest = create_backup(_make_db(tmp_path / "source.sqlite3"), backup, signing_key=private)
    created = datetime.fromisoformat(manifest["created_at"])
    report = build_recovery_readiness(
        directory, trusted_public_key=public, now=created + timedelta(days=3),
        max_backup_age_hours=24,
    )
    assert report["status"] == "DEGRADED"
    assert "newest_verified_backup_exceeds_maximum_age" in report["issues"]


def test_recovery_readiness_cli_fails_closed_without_trust_anchor(tmp_path, capsys):
    from nexora.cli import main

    directory = tmp_path / "backups"
    directory.mkdir()
    result = main(["recovery-readiness", "--directory", str(directory)])
    payload = json.loads(capsys.readouterr().out)
    assert result == 2
    assert payload["status"] == "BLOCKED_TRUST_ANCHOR"



def test_readiness_reports_independently_witnessed_simulation(tmp_path):
    from nexora.recovery_history import record_recovery_simulation

    directory = tmp_path / "backups"
    directory.mkdir()
    backup_private, backup_public = tmp_path / "backup-private.pem", tmp_path / "backup-public.pem"
    witness_private, witness_public = tmp_path / "witness-private.pem", tmp_path / "witness-public.pem"
    generate_backup_signing_key(backup_private, backup_public)
    generate_backup_signing_key(witness_private, witness_public)
    backup = directory / "verified.sqlite3"
    manifest = create_backup(_make_db(tmp_path / "source.sqlite3"), backup, signing_key=backup_private)
    record_recovery_simulation(
        backup, backup_trusted_key=backup_public,
        witness_private_key=witness_private,
        witness_receipt_log=tmp_path / "witness" / "receipts.jsonl",
        history_log=tmp_path / "recovery" / "history.jsonl",
    )
    report = build_recovery_readiness(
        directory, trusted_public_key=backup_public,
        now=datetime.fromisoformat(manifest["created_at"]) + timedelta(minutes=1),
        history_log=tmp_path / "recovery" / "history.jsonl",
        witness_receipt_log=tmp_path / "witness" / "receipts.jsonl",
        trusted_witness_public_key=witness_public,
    )
    assert report["recovery_simulation"] == "PASSED"
    assert report["simulation_count"] == 1
    assert report["witness_chain_valid"] is True
