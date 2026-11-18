import sqlite3

import pytest

from nexora.storage.migrations.runner import apply_migrations


def test_migrations_apply_in_order_and_are_idempotent():
    db = sqlite3.connect(":memory:")
    migrations = {
        1: lambda connection: connection.execute("CREATE TABLE sample(value TEXT)"),
        2: lambda connection: connection.execute("ALTER TABLE sample ADD COLUMN source TEXT"),
    }
    assert apply_migrations(db, migrations) == 2
    assert apply_migrations(db, migrations) == 2
    assert db.execute("PRAGMA user_version").fetchone()[0] == 2


def test_missing_migration_fails_without_advancing_version():
    db = sqlite3.connect(":memory:")
    with pytest.raises(RuntimeError, match="migration_missing:1"):
        apply_migrations(db, {2: lambda connection: None})
    assert db.execute("PRAGMA user_version").fetchone()[0] == 0


def test_failed_migration_rolls_back_entire_batch():
    db = sqlite3.connect(":memory:")
    def fail(connection):
        connection.execute("CREATE TABLE partial(value TEXT)")
        raise RuntimeError("migration failed")
    migrations = {
        1: lambda connection: connection.execute("CREATE TABLE first(value TEXT)"),
        2: fail,
    }
    with pytest.raises(RuntimeError, match="migration failed"):
        apply_migrations(db, migrations)
    assert db.execute("PRAGMA user_version").fetchone()[0] == 0
    names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert names == set()


def test_existing_transaction_is_rejected_without_interference():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE existing(value TEXT)")
    db.execute("BEGIN")
    with pytest.raises(RuntimeError, match="already_in_transaction"):
        apply_migrations(db, {1: lambda connection: None})
    assert db.in_transaction
    db.rollback()


def test_newer_database_schema_fails_closed():
    db = sqlite3.connect(":memory:")
    db.execute("PRAGMA user_version=9")
    with pytest.raises(RuntimeError, match="newer_than_application"):
        apply_migrations(db, {1: lambda connection: None})


def test_registry_rejects_bool_and_invalid_migration_entries():
    db = sqlite3.connect(":memory:")
    with pytest.raises(ValueError, match="registry_invalid"):
        apply_migrations(db, {True: lambda connection: None})
    with pytest.raises(ValueError, match="registry_invalid"):
        apply_migrations(db, {1: "not-callable"})


def test_old_schema_fixture_migrates_preserving_rows(tmp_path):
    path = tmp_path / "old.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT NOT NULL)")
        db.execute("INSERT INTO notes(body) VALUES('preserve me')")
        db.execute("PRAGMA user_version=1")
    with sqlite3.connect(path) as db:
        version = apply_migrations(db, {
            2: lambda connection: connection.execute(
                "ALTER TABLE notes ADD COLUMN source TEXT NOT NULL DEFAULT 'legacy'"
            ),
            3: lambda connection: connection.execute(
                "CREATE INDEX notes_source_idx ON notes(source)"
            ),
        })
        assert version == 3
        assert db.execute("SELECT body, source FROM notes").fetchone() == ("preserve me", "legacy")
