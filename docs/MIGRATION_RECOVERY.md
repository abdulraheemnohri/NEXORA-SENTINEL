# Recovery Readiness

## Configuration

The optional `config/recovery.json` file controls diagnostic thresholds. Missing configuration uses safe built-in defaults. Existing malformed or unknown fields fail closed.

- `backup_directory`: explicit backup inventory scope
- `trusted_public_key`: independently enrolled Ed25519 public key path; blank means trust is not established
- `retention_days` and `keep_latest`: proposal-only retention thresholds
- `max_backup_age_hours`: freshness threshold for readiness
- `min_verified_points`: minimum verified recovery-point count
- `require_simulation_confirmation`: remains true
- `history_log`: append-only recovery simulation metadata log
- `witness_receipt_log`: Ed25519 witness receipt chain
- `witness_private_key` / `witness_public_key`: separate witness key pair paths
- `audit_log`: hash-chained audit log receiving simulation events
- `automatic_restore` and `automatic_deletion`: must remain false; true is rejected

Example:

```bash
nexora recovery-readiness --config config/recovery.json
nexora recovery-readiness --directory data/backups \
  --trusted-key /secure/off-device/backup-signing-key.pub.pem \
  --max-backup-age-hours 168 --min-verified-points 2
```

## Readiness scoring

The score starts at 100 when at least one recovery point verifies. It loses 30 points when the newest verified point is older than the configured freshness threshold, 30 when the verified point count is below the configured minimum, and up to 20 for unusable artifacts (5 per artifact). No verified point yields 0. The status is `READY`, `DEGRADED`, `NOT_READY`, or `BLOCKED_TRUST_ANCHOR`.

This is a deterministic operational indicator, not a guarantee of disaster recovery. A successful isolated simulation is not inferred from backup validity. Readiness reports `PASSED` only when a matching event is present in the independently verified witness chain; otherwise it reports `NOT_RECORDED`, `BLOCKED_TRUST_ANCHOR`, or `INVALID`.

## Safety

Readiness checks are read-only. Retention decisions remain proposals. Restore simulation requires explicit confirmation and uses a temporary directory. Automatic restore and automatic deletion are prohibited by configuration validation. Live database replacement remains a separately approved operator action.


## Persistent witnessed simulation history

A simulation can now be recorded as a metadata-only event, linked to an independently signed Ed25519 witness receipt, and appended to the hash-chained audit log. The event records the backup SHA-256, simulation ID/time, SQLite integrity result, schema version, table count and cleanup outcome. It does not store database contents or absolute filesystem paths.

Create a dedicated witness key pair. It must be separate from the backup-signing key:

```bash
nexora backup-keygen \
  --private-key data/recovery-witness-signing-key.pem \
  --public-key data/recovery-witness-signing-key.pub.pem
```

Keep the private key protected and provision the public key through a separate trusted channel. Then run an explicitly confirmed simulation:

```bash
nexora recovery-simulate data/backups/registry.sqlite3 \
  --trusted-key /secure/off-device/backup-signing-key.pub.pem \
  --confirm-simulation
nexora recovery-history \
  --trusted-witness-key data/recovery-witness-signing-key.pub.pem
nexora audit
```

The CLI defaults to:
- `data/recovery/history.jsonl` — metadata-only event records
- `data/recovery-witness/receipts.jsonl` — signed, chained witness receipts
- `data/recovery-witness-signing-key.pem` — independent witness private key
- `data/recovery-witness-signing-key.pub.pem` — independently pinned verification key
- `data/audit.jsonl` — hash-chained audit events

Override paths with `--history-log`, `--witness-log`, `--witness-key`, `--trusted-witness-key` and `--audit-log` where supported. A missing witness private key causes recording to fail; an unsigned event is never reported as a trusted simulation. The history reader verifies the entire witness chain and each event digest, excludes unreceipted events, and is read-only. A damaged receipt chain blocks the report.

This is local cryptographic evidence, not remote attestation. Protect the witness private key and retain an independently stored public-key pin. The audit log and witness log are separate chains; the audit entry references the simulation event hash and witness sequence. A simulation does not authorize a production restore, delete backups, or replace a live database.
