# SQLite Migration and Recovery

NEXORA Sentinel uses explicit schema versions via SQLite `PRAGMA user_version`.

## Safety contract

1. Validate the complete migration registry and required contiguous version sequence.
2. Refuse a database whose schema version is newer than this application.
3. Refuse to run inside a caller-owned transaction.
4. Verify SQLite integrity before and after migration.
5. Apply all pending migration callbacks in one `BEGIN IMMEDIATE` transaction.
6. Commit the schema and `user_version` together, or roll the entire batch back.
7. The recovery orchestrator creates and cryptographically verifies a signed online backup before opening the database for migration.
8. On failure, it restores the backup to a separate recovery-copy path. It never overwrites the original database automatically.

Migration callbacks must use `execute` or `executemany`. They must not call `commit`, `rollback`, or `executescript`; transaction ownership belongs to the migration runner. Keep callbacks deterministic and local. Network access, model inference, tool execution, and external side effects are prohibited in migrations.

## Python API

```python
from pathlib import Path
from nexora.storage.migrations.recovery import migrate_with_backup

report = migrate_with_backup(
    Path("data/registry.sqlite3"),
    migrations={2: migration_to_v2, 3: migration_to_v3},
    signing_key=Path("data/backup-signing-key.pem"),
    trusted_public_key=Path("data/backup-signing-key.pub.pem"),
    backup_path=Path("data/backups/pre-migration.sqlite3"),
    recovery_copy_path=Path("data/recovery/registry-before-migration.sqlite3"),
)
```

The signing public key must be an independently trusted key. Never treat a public key embedded beside an untrusted backup as a trust anchor. Protect the private key and retain backups outside the device where practical.

## Failure handling

A `MigrationRecoveryError` exposes `backup` and `recovery_copy` paths. Inspect both and preserve the original database. Replacing or rolling back the live database is a separate operator-controlled procedure and is intentionally not automated.

## Fault-injection coverage

The backup tests inject failures during database snapshot validation, publication of the database/manifest pair, and restored-copy validation. They assert that failed operations do not leave a published partial destination, temporary artifacts are cleaned up, and the source database remains unchanged. These are controlled exception-path tests; they do not simulate physical power loss, filesystem corruption, storage-controller cache loss, or every platform's hard-link semantics. Keep independent copies of important backups and test restore on the target filesystem.

A crash between publishing the database and its manifest can leave an unpaired backup file. Verification rejects it because the signed manifest is absent. Do not manually manufacture a manifest for that file; preserve it for investigation and create a fresh backup to a new destination.

## Verification

Run:

```bash
python -m pytest tests/test_migrations.py tests/test_migration_recovery.py tests/test_backup.py
```

These tests exercise historical schema fixtures, all-or-nothing migration transactions, backup-before-migration, injected failures, preservation of the original database, and restore to a new path.
