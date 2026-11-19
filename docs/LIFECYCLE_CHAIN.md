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

## Operator checkpoint workflow

Initialize/upgrade the registry through its normal application path, then
inspect the local chain:

```bash
nexora lifecycle-history
```

Create a dedicated Ed25519 witness key pair using the existing backup key
generator (do not reuse the backup signer):

```bash
nexora backup-keygen --private-key ./keys/lifecycle-witness-private.pem --public-key ./keys/lifecycle-witness-public.pem
```

After securely transferring the public key to the verification environment,
create a signed checkpoint:

```bash
nexora lifecycle-chain-attest --witness-key ./keys/lifecycle-witness-private.pem --witness-log /separate-witness-storage/lifecycle.jsonl --confirm
```

Verify the current registry head against the signed witness log:

```bash
nexora lifecycle-chain-verify --witness-log /separate-witness-storage/lifecycle.jsonl --trusted-witness-key ./keys/lifecycle-witness-public.pem
```

The latest witness receipt must match the current chain head. If more registry
events are appended after a checkpoint, verification reports
`ANCHOR_MISMATCH` until a new checkpoint is explicitly created. Keep the
witness log and public trust anchor on independently controlled storage; a
witness log stored beside the registry on the same writable device is not an
independent trust boundary. Back up the witness log and preserve its public
key through a separate trusted channel.
