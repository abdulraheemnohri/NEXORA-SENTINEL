# Recovery Readiness

## Configuration

The optional `config/recovery.json` file controls diagnostic thresholds. Missing configuration uses safe built-in defaults. Existing malformed or unknown fields fail closed.

- `backup_directory`: explicit backup inventory scope
- `trusted_public_key`: independently enrolled Ed25519 public key path; blank means trust is not established
- `retention_days` and `keep_latest`: proposal-only retention thresholds
- `max_backup_age_hours`: freshness threshold for readiness
- `min_verified_points`: minimum verified recovery-point count
- `require_simulation_confirmation`: remains true
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

This is a deterministic operational indicator, not a guarantee of disaster recovery. A successful isolated simulation is not inferred from backup validity; until a separately recorded simulation-history feature exists, the report explicitly says `NOT_RECORDED`.

## Safety

Readiness checks are read-only. Retention decisions remain proposals. Restore simulation requires explicit confirmation and uses a temporary directory. Automatic restore and automatic deletion are prohibited by configuration validation. Live database replacement remains a separately approved operator action.
