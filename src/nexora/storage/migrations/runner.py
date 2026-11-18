"""Small transactional SQLite user_version migration runner."""
import sqlite3
from collections.abc import Callable

Migration = Callable[[sqlite3.Connection], None]


def apply_migrations(connection: sqlite3.Connection, migrations: dict[int, Migration]) -> int:
    if any(type(version) is not int or version < 1 or not callable(migration)
           for version, migration in migrations.items()):
        raise ValueError("migration_registry_invalid")
    current = int(connection.execute("PRAGMA user_version").fetchone()[0])
    target = max(migrations, default=current)
    if current > target:
        raise RuntimeError("database_schema_is_newer_than_application")
    for version in range(current + 1, target + 1):
        migration = migrations.get(version)
        if migration is None:
            raise RuntimeError(f"migration_missing:{version}")
        connection.execute("BEGIN IMMEDIATE")
        try:
            migration(connection)
            connection.execute(f"PRAGMA user_version = {version}")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        current = version
    return current
