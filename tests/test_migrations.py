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


def test_failed_migration_rolls_back_schema_and_version():
    db = sqlite3.connect(":memory:")
    def fail(connection):
        connection.execute("CREATE TABLE partial(value TEXT)")
        raise RuntimeError("migration failed")
    with pytest.raises(RuntimeError, match="migration failed"):
        apply_migrations(db, {1: fail})
    assert db.execute("PRAGMA user_version").fetchone()[0] == 0
    assert db.execute("SELECT name FROM sqlite_master WHERE name='partial'").fetchone() is None
