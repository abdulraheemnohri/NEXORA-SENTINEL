# Cryptographic Lifecycle History v1

## What changed

New lifecycle, revocation and rollback records are appended to a single ordered
SHA-256 hash chain in the same SQLite transaction as their source event.
Canonical JSON payloads include every column of the source event. Verification
checks sequence continuity, previous hashes, event hashes, exact source-row
equality, and coverage of every source event created after chain activation.

## Legacy data

On first chain initialization, the maximum existing event ID in each source
table is recorded as its legacy watermark. Existing records at or below that
watermark are not retroactively hashed, signed or attested. Reports keep
`legacy_unverified=true`. A missing chain schema is reported as NOT_MIGRATED;
it is not silently initialized by read-only diagnostics.

## Trust boundary

The database hash chain detects accidental changes and ordinary tampering
when the chain head is retained. A privileged attacker able to rewrite the
database can rewrite the chain and its watermark metadata too. Therefore the
local chain is not an independent trust anchor.

For stronger protection, export signed chain-head checkpoints to an
independently controlled witness host or offline medium. Keep the witness
private key and trusted public key outside the registry database and preferably
outside the same device. A future milestone will add an operator-facing
checkpoint/verification workflow; no remote service is implied by this local
chain implementation.

No lifecycle promotion, rollback execution, policy change, capability
execution, automatic repair or autonomous tool use is enabled.
