import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nexora.backup import create_backup, generate_backup_signing_key
from nexora.recovery_planner import (
    RecoveryPlanningError,
    build_recovery_plan,
    simulate_recovery,
)


def _database(path: Path, value: str) -> Path:
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE sample(value TEXT)")
        db.execute("INSERT INTO sample VALUES(?)", (value,))
    return path


def _keys(path: Path):
    private, public = path / "private.pem", path / "public.pem"
    generate_backup_signing_key(private, public)
    return private, public


def _backup(source: Path, destination: Path, private: Path):
    create_backup(source, destination, signing_key=private)
    return destination


def test_recovery_plan_ranks_valid_points_and_proposes_retention_only(tmp_path):
    directory = tmp_path / "backups"
    directory.mkdir()
    private, public = _keys(tmp_path)
    first = _backup(_database(tmp_path / "first.db", "first"), directory / "first.sqlite3", private)
    second = _backup(_database(tmp_path / "second.db", "second"), directory / "second.sqlite3", private)
    old = datetime.now(UTC) - timedelta(days=90)
    import os
    os.utime(first, (old.timestamp(), old.timestamp()))
    os.utime(Path(str(first) + ".manifest.json"), (old.timestamp(), old.timestamp()))
    report = build_recovery_plan(
        directory, trusted_public_key=public, retention_days=30,
        keep_latest=1, now=datetime.now(UTC),
    )
    assert report["valid_recovery_points"] == 2
    decisions = {item["name"]: item["decision"] for item in report["retention"]["proposals"]}
    assert decisions["second.sqlite3"] == "KEEP"
    assert decisions["first.sqlite3"] == "REVIEW_FOR_RETENTION"
    assert all(not item["deletion_performed"] for item in report["retention"]["proposals"])
    assert first.exists() and second.exists()


def test_recovery_plan_rejects_invalid_retention_settings(tmp_path):
    directory = tmp_path / "backups"
    directory.mkdir()
    _, public = _keys(tmp_path)
    with pytest.raises(RecoveryPlanningError):
        build_recovery_plan(directory, trusted_public_key=public, retention_days=0)


def test_simulation_requires_confirmation_and_removes_temporary_restore(tmp_path):
    private, public = _keys(tmp_path)
    backup = _backup(
        _database(tmp_path / "source.db", "simulation"),
        tmp_path / "backup.sqlite3", private,
    )
    with pytest.raises(RecoveryPlanningError):
        simulate_recovery(backup, trusted_public_key=public)
    result = simulate_recovery(backup, trusted_public_key=public, confirm=True)
    assert result["simulation"] == "PASSED"
    assert result["temporary_output_removed"] is True
    assert result["live_database_touched"] is False
    assert backup.exists()
    assert not (tmp_path / "simulation.sqlite3").exists()


def test_simulation_rejects_symlink_backup(tmp_path):
    _, public = _keys(tmp_path)
    target = tmp_path / "real.sqlite3"
    _database(target, "safe")
    link = tmp_path / "link.sqlite3"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(RecoveryPlanningError):
        simulate_recovery(link, trusted_public_key=public, confirm=True)
