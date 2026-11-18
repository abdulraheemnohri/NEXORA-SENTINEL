# Security architecture and operational guidance

## Default-deny posture

Unknown actions and unknown capability interactions are denied or escalated. The kill switch blocks policy decisions. Runtime policy registration is disabled. No shell, network, model, tool or staged-code execution is enabled by this release.

## Approval keys

Generate Ed25519 keys locally and keep private keys outside the repository with restrictive file permissions. Enroll a public key only after independently verifying its fingerprint. Receipts are short-lived, scope-bound and single-use. A signature proves possession of the enrolled key, not the real-world identity of its holder.

## Audit and backup

The local audit log is hash chained and detects ordinary modification; it is not tamper-proof against an attacker who can rewrite the whole file. SQLite backups use the online backup API and are checked with SQLite integrity_check. The SHA-256 sidecar is not signed: an attacker able to replace both backup and manifest can recompute the digest. Store a trusted copy of the manifest or add a separately controlled signature/witness for stronger authenticity.

## Independent witness receipts

Witness receipts are signed with a key distinct from the backup signer. Appends and verification use an adjacent `receipts.jsonl.lock` sidecar to serialize cooperating processes on POSIX and Windows. Keep the receipt log, lock file, and private key on storage with appropriate access controls; all writers must use the NEXORA witness API and the same log path. A process crash that leaves a partial final line causes verification and subsequent appends to fail closed; preserve the damaged log for investigation rather than editing or truncating it. A local lock does not protect against hostile processes that bypass the API, replace the log, or operate on an untrusted filesystem. For genuine independence, hold the witness private key on a separately administered host.

## Recovery

Restore refuses to overwrite an existing destination. Verify backups before restore. Keep the original database untouched until the restored copy is checked and the operator has reviewed it.

## Scope

This project is not a hardened OS sandbox, secure boot, remote witness, hardware-backed identity provider, or production autonomous agent. Report vulnerabilities privately to the repository maintainer.


## Approval signing-key lifecycle

Trusted approval keys expire after 365 days by default. Enrollment and rotation/renewal accept `--validity-days` from 1 through 730. Existing trust-store rows are migrated to an expiry timestamp 365 days after their original enrollment time; they are not silently granted a fresh lifetime. Expired keys cannot authorize new receipts. Renewal uses a newly generated keypair and atomically revokes the old key while enrolling the replacement; do not extend or reuse the old private key.

```bash
nexora approval enroll --public-key /secure/operator.pub.pem --label "operator-1" --validity-days 365
nexora approval renew \\
  --old-fingerprint OLD_FINGERPRINT \\
  --new-public-key /secure/operator-next.pub.pem \\
  --new-label "operator-1-renewed" \\
  --reason "annual key renewal" \\
  --validity-days 365
nexora approval keys
```

`approval keys` reports the public-key expiry timestamp. Expiration is enforced at receipt verification time, independently of the short receipt TTL. Keep system clocks synchronized; the receipt clock-skew allowance does not extend a signing key's lifetime.

Use a dedicated Ed25519 keypair for lifecycle approvals. Generate it locally:

```bash
nexora approval keygen \
  --private-key /secure/nexora/approval-private.pem \
  --public-key /secure/nexora/approval-public.pem
```

The private key is created with owner-only permissions and is never written to the repository. Enroll only after verifying the public-key fingerprint through a separate trusted channel:

```bash
nexora approval enroll --public-key /secure/nexora/approval-public.pem --label "primary-operator"
nexora approval keys
nexora approval history
```

For planned rotation, generate a replacement keypair first, verify its fingerprint independently, then atomically enroll the new public key and revoke the previous key:

```bash
nexora approval rotate \
  --old-fingerprint OLD_FINGERPRINT \
  --new-public-key /secure/nexora/approval-next-public.pem \
  --new-label "operator-2027" \
  --reason "scheduled rotation"
```

The registry transaction makes the replacement active and old key inactive together. If the transaction fails, the old key remains active. Revocation and rotation metadata are recorded in append-only `signing_key_events`; public trust metadata is queryable, but private key bytes are never stored in SQLite. Revocation immediately blocks future receipt consumption; it does not retroactively rewrite historical lifecycle events.

Issue a short-lived receipt for one exact capability transition and evidence set:

```bash
nexora approval issue \
  --private-key /secure/nexora/approval-private.pem \
  --capability-id 42 --transition APPROVED \
  --evidence human_approval \
  --approver-id operator-1 \
  --output /secure/approval-42.json
```

Apply it through the registry:

```bash
nexora registry-transition 42 APPROVED \
  --evidence human_approval \
  --approver-id operator-1 \
  --approval-receipt /secure/approval-42.json
```

The receipt is bound to capability ID, transition, approver label and a digest of the sorted evidence set; it expires within at most 15 minutes and is single-use. Receipt nonce consumption and lifecycle-state update share the same SQLite transaction. Invalid, expired, replayed, revoked-key or scope-mismatched receipts do not advance state.

A key signature is not proof of a person's legal identity. Key custody, fingerprint verification, operator identity checks and out-of-band approval remain organizational responsibilities. The local SQLite trust store is not remotely tamper-proof; back it up and protect the host. Do not rotate keys by copying private material into the repository.
