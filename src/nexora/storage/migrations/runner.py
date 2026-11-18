"""Fail-closed, all-or-nothing SQLite schema migration runner.

Migration callbacks must use connection.execute/executemany and must not call
commit(), rollback(), or executescript(), because the runner owns the transaction.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Callable, Mapping

Migration = Callable[[sqlite3.Connection], None]


def _validate_registry(migrations: Mapping[int, Migration]) -> None:
    if not isinstance(migrations, Mapping):
        raise TypeError("migration_registry_invalid")
    for version, migration in migrations.items():
        if type(version) is not int or version < 1 or not callable(migration):
            raise ValueError("migration_registry_invalid")


def _integrity_check(connection: sqlite3.Connection) -> None:
    rows = connection.execute("PRAGMA integrity_check").fetchall()
    if rows != [("ok",)]:
        raise RuntimeError("sqlite_integrity_check_failed")


def apply_migrations(connection: sqlite3.Connection, migrations: Mapping[int, Migration]) -> int:
    """Apply every pending migration in one transaction; never partially advance.

    The caller retains ownership of the connection. A missing version, failed
    callback, failed integrity check, or newer database schema aborts the whole
    batch and restores both schema and user_version to their pre-call state.
    """
    _validate_registry(migrations)
    if connection.in_transaction:
        raise RuntimeError("migration_connection_already_in_transaction")

    current = int(connection.execute("PRAGMA user_version").fetchone()[0])
    target = max(migrations, default=current)
    if current < 0:
        raise RuntimeError("database_schema_version_invalid")
    if current > target:
        raise RuntimeError("database_schema_is_newer_than_application")
    pending = range(current + 1, target + 1)
    missing = [version for version in pending if version not in migrations]
    if missing:
        raise RuntimeError(f"migration_missing:{missing[0]}")
    if current == target:
        _integrity_check(connection)
        return current

    connection.execute("BEGIN IMMEDIATE")
    try:
        _integrity_check(connection)
        for version in pending:
            migrations[version](connection)
            connection.execute(f"PRAGMA user_version = {version}")
        _integrity_check(connection)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return target
