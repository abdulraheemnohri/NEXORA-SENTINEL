# Backup Inventory and Recovery Readiness

## Read-only inventory

The inventory command inspects only direct children of the explicitly supplied backup directory. It does not recurse, create directories, modify manifests, repair databases, delete files, or restore data.

```bash
nexora backup-inventory --directory data/backups
nexora backup-inventory --directory data/backups --trusted-key /secure/off-device/backup-signing-key.pub.pem
```

Without an independently trusted public key, paired backup files are reported as `TRUST_ANCHOR_REQUIRED`; the manifest's own signer fingerprint is not a trust anchor. With a trusted key, each paired SQLite backup is checked using the normal signature, SHA-256, metadata, and SQLite integrity verifier.

Statuses include `VALID`, `TRUST_ANCHOR_REQUIRED`, `ORPHAN_DATABASE`, `ORPHAN_MANIFEST`, `INVALID`, and `UNSAFE_SYMLINK`. The report includes file size, filesystem modification age, signer fingerprint, schema version and table count where safely available. Modification time is an inventory hint, not proof of backup creation time.

## Recovery safety boundary

Inventory is diagnostic only. It does not select a recovery point, delete old backups, change retention, or replace the live database. An invalid or orphaned artifact should be preserved for investigation; create a fresh backup rather than manufacturing a missing manifest.

The next recovery stage can add recovery-point ranking, retention proposals, and isolated restore simulation. Any simulation must target a new temporary path. Replacing a live database remains a separate, explicitly approved operator procedure.

## Tests

```bash
python -m pytest tests/test_backup.py tests/test_backup_inventory.py
```

The inventory tests cover empty/missing directories, orphan artifacts, absent trust anchors, valid signatures, tampering, malformed manifests, and symlink refusal.