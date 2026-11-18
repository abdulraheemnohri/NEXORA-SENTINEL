import sqlite3

import pytest

from nexora.backup import generate_backup_signing_key
from nexora.storage.migrations.recovery import MigrationRecoveryError, migrate_with_backup


def _db(path):
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE records(value TEXT NOT NULL)")
        db.execute("INSERT INTO records VALUES('keep-this')")
        db.execute("PRAGMA user_version=1")
    return path


def _keys(tmp_path):
    private, public = tmp_path / "signing.pem", tmp_path / "trusted.pub.pem"
    generate_backup_signing_key(private, public)
    return private, public


def test_backup_precedes_migration_and_success_reports_versions(tmp_path):
    database = _db(tmp_path / "registry.sqlite3")
    private, public = _keys(tmp_path)
    report = migrate_with_backup(
        database,
        {2: lambda db: db.execute("ALTER TABLE records ADD COLUMN source TEXT DEFAULT 'old'")},
        signing_key=private,
        trusted_public_key=public,
        backup_path=tmp_path / "before.sqlite3",
        recovery_copy_path=tmp_path / "recovery.sqlite3",
    )
    assert (report.previous_version, report.current_version) == (1, 2)
    assert (tmp_path / "before.sqlite3").is_file()
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT value, source FROM records").fetchone() == ("keep-this", "old")


def test_failed_migration_rolls_back_and_creates_verified_recovery_copy(tmp_path):
    database = _db(tmp_path / "registry.sqlite3")
    private, public = _keys(tmp_path)
    def fail(db):
        db.execute("CREATE TABLE half_done(value TEXT)")
        raise RuntimeError("injected migration failure")
    with pytest.raises(MigrationRecoveryError, match="migration_failed") as error:
        migrate_with_backup(
            database, {2: fail},
            signing_key=private, trusted_public_key=public,
            backup_path=tmp_path / "before.sqlite3",
            recovery_copy_path=tmp_path / "recovery.sqlite3",
        )
    assert error.value.backup.is_file()
    assert error.value.recovery_copy.is_file()
    with sqlite3.connect(database) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert db.execute("SELECT value FROM records").fetchone()[0] == "keep-this"
        assert db.execute(
            "SELECT name FROM sqlite_master WHERE name='half_done'"
        ).fetchone() is None
    with sqlite3.connect(error.value.recovery_copy) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert db.execute("SELECT value FROM records").fetchone()[0] == "keep-this"


def test_backup_failure_prevents_any_migration(tmp_path):
    database = _db(tmp_path / "registry.sqlite3")
    private, public = _keys(tmp_path)
    with pytest.raises(Exception):
        migrate_with_backup(
            database, {2: lambda db: db.execute("CREATE TABLE unsafe(value TEXT)")},
            signing_key=private, trusted_public_key=public,
            backup_path=tmp_path / "existing.sqlite3",
            recovery_copy_path=tmp_path / "recovery.sqlite3",
        )
    with sqlite3.connect(database) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert db.execute(
            "SELECT name FROM sqlite_master WHERE name='unsafe'"
        ).fetchone() is None
