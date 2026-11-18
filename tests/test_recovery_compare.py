import sqlite3
from pathlib import Path

import pytest

from nexora.backup import create_backup, generate_backup_signing_key
from nexora.recovery_compare import RecoveryComparisonError, compare_recovery_points


def _database(path: Path, *, version: int, extra_table: bool = False) -> Path:
    with sqlite3.connect(path) as db:
        db.execute(f"PRAGMA user_version={version}")
        db.execute("CREATE TABLE base(value TEXT)")
        if extra_table:
            db.execute("CREATE TABLE added(value INTEGER)")
    return path


def test_compare_verified_recovery_points_reports_schema_delta(tmp_path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    generate_backup_signing_key(private, public)
    older = tmp_path / "older.sqlite3"
    newer = tmp_path / "newer.sqlite3"
    create_backup(_database(tmp_path / "old.db", version=1), older, signing_key=private)
    create_backup(_database(tmp_path / "new.db", version=2, extra_table=True), newer, signing_key=private)

    result = compare_recovery_points(older, newer, trusted_public_key=public)
    assert result["valid"] is True
    assert result["read_only"] is True
    assert result["schema_comparison"]["same_schema"] is False
    assert result["schema_comparison"]["tables_added"] == ["added"]
    assert result["schema_comparison"]["migration_version_delta"] == 1
    assert result["data_equality_checked"] is False
    assert older.is_file() and newer.is_file()


def test_compare_refuses_same_or_untrusted_backup(tmp_path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    wrong_private, wrong_public = tmp_path / "wrong-private.pem", tmp_path / "wrong-public.pem"
    generate_backup_signing_key(private, public)
    generate_backup_signing_key(wrong_private, wrong_public)
    backup = tmp_path / "backup.sqlite3"
    create_backup(_database(tmp_path / "source.db", version=1), backup, signing_key=private)
    with pytest.raises(RecoveryComparisonError, match="must_be_distinct"):
        compare_recovery_points(backup, backup, trusted_public_key=public)
    with pytest.raises(RecoveryComparisonError, match="verification_failed"):
        compare_recovery_points(backup, tmp_path / "missing.sqlite3", trusted_public_key=wrong_public)


def test_compare_refuses_symlinked_recovery_points(tmp_path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    generate_backup_signing_key(private, public)
    real = tmp_path / "real.sqlite3"
    create_backup(_database(tmp_path / "source.db", version=1), real, signing_key=private)
    alias = tmp_path / "alias.sqlite3"
    alias.symlink_to(real)
    other = tmp_path / "other.sqlite3"
    create_backup(_database(tmp_path / "other.db", version=2), other, signing_key=private)
    with pytest.raises(RecoveryComparisonError, match="symlink"):
        compare_recovery_points(alias, other, trusted_public_key=public)
