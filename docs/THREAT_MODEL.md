# Threat model

## Protected assets

- Operator approval keys and their trust pins.
- Capability registry and append-only lifecycle records.
- Backup snapshots, manifests and restore destinations.
- Audit and witness evidence.
- Emergency stop state and immutable safety policy.

## Controls

- Unknown actions are denied; runtime policy mutation is disabled.
- Emergency stop blocks policy decisions.
- Audit append refuses a broken local hash chain.
- APPROVED/ENABLED lifecycle transitions require scoped Ed25519 receipts and one-time nonce consumption in the same SQLite transaction as the state change.
- SQLite backups use the online backup API, signed canonical manifests, externally supplied trusted public keys, SQLite integrity checks and non-overwriting restore.
- Independent witness receipts use a distinct Ed25519 key, signed sequence numbers and a previous-receipt hash chain.
- No generated-code executor or unrestricted network tools exist in this release.

## Limitations and residual risks

- A signature proves possession of a private key, not the real-world identity of its holder. Key enrollment and public-key distribution require an out-of-band trust procedure.
- A backup SHA-256 digest alone is not authentication; signed manifest verification requires a trusted public key that is obtained separately from the backup.
- The witness implementation is a separate local receipt stream, not a remote or hardware trust anchor. Independence depends on the witness key and process being controlled separately.
- Multi-process locking for witness appends is not implemented.
- Local files can be modified by an attacker with sufficient filesystem privileges. Keep signing keys private, retain off-device copies of trusted public keys and export critical evidence to independently controlled storage.
- No OS-enforced sandbox or permission-granted tool executor is implemented.
- Formal model checking covers the documented lifecycle abstraction, not every Python runtime behavior.
