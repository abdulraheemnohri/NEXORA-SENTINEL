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


## Emergency approval-key recovery

Emergency recovery is a separate trust domain from ordinary capability approval. Enroll two or three recovery authorities before an incident, using independently generated Ed25519 keypairs and independently verified fingerprints. Recovery authority keys must not be the same keys used for normal approval signing. Keep each recovery private key under separate custody; the recommended operational arrangement is three authorities with a two-of-three threshold.

Generate each authority keypair on its own controlled device or account:

```bash
nexora approval keygen --private-key /secure/recovery-1.pem --public-key /secure/recovery-1.pub.pem
nexora approval recovery-enroll --public-key /secure/recovery-1.pub.pem --authority-id recovery-1 --label "Recovery custodian 1"
```

Repeat for recovery-2 and recovery-3. Verify fingerprints out-of-band before enrollment and review the enrolled list:

```bash
nexora approval recovery-authorities
```

During an incident, generate a new ordinary approval keypair. Each of two independent recovery authorities reviews the incident and signs the exact same recovery operation. Authorizations bind the old fingerprint, replacement public key, replacement label, reason, authority identity, expiry and unique nonce:

```bash
nexora approval recovery-issue \\
  --private-key /secure/recovery-1.pem \\
  --authority-id recovery-1 \\
  --old-fingerprint OLD_APPROVAL_FINGERPRINT \\
  --new-public-key /secure/operator-replacement.pub.pem \\
  --new-label "operator-recovered" \\
  --reason "operator key compromised" \\
  --output /secure/recovery-1.json
```

Repeat on the second authority's controlled device with its own private key and output path. Then apply both authorizations:

```bash
nexora approval recover \\
  --old-fingerprint OLD_APPROVAL_FINGERPRINT \\
  --new-public-key /secure/operator-replacement.pub.pem \\
  --new-label "operator-recovered" \\
  --reason "operator key compromised" \\
  --authorization /secure/recovery-1.json /secure/recovery-2.json
```

The recovery transaction verifies two or three distinct, active, unexpired authority keys and signatures; checks the exact operation scope; consumes all nonces; enrolls the replacement approval key; revokes the old approval key; and appends a recovery event in one SQLite transaction. Invalid signatures, duplicate authorities, expired authorizations, replay, revoked/expired recovery keys, or an inactive target key fail closed. Authorization lifetime is at most ten minutes. Recovery authorities can be revoked with the API and their public status/history is available through `approval recovery-authorities` and `approval recovery-history`. Revoke a compromised authority with `nexora approval recovery-revoke --fingerprint AUTHORITY_FINGERPRINT --reason "custodian device compromised"`; revocation is immediate and append-only.

This is not a remote or hardware-backed recovery service. Recovery authority trust pins live in the local SQLite database, so an attacker with unrestricted write access to that host/database may tamper with local trust state. Keep the host and database protected, retain independently controlled backups, and perform authority enrollment/fingerprint verification out-of-band. Two keys prove two signing-key possessions, not two real-world identities. The recovery mechanism does not restore lost data, recover private keys, or bypass OS access controls.

## Signed capability revocation and rollback records

Capability revocation requires two to five distinct approver IDs and distinct trusted Ed25519 signing-key fingerprints. The signed `REVOKE` receipts bind the exact capability, evidence set, revocation reason, expiry, nonce and signer. The registry consumes all receipt nonces, sets the persistent revocation control state, and appends the signed receipt metadata in one SQLite write transaction. Every lifecycle transition checks this control state and refuses to proceed once revoked. The same threshold is currently applied to every capability because the catalogue does not provide a trustworthy criticality classification.

A signed `ROLLBACK` receipt set authorizes only an auditable rollback record. It does not execute code, deploy artifacts, restore a previous version, or reverse a capability revocation. The exact source release, target release and reason are included in the signed evidence. Receipt payloads and signer fingerprints are retained in append-only event tables.

These controls protect against ordinary application-level replay and concurrent requests. They do not protect a local SQLite database from an attacker with unrestricted filesystem or process access; protect the host, keep external backups, and independently verify operator identities and key fingerprints. A two-key threshold proves possession of two distinct private keys, not two distinct people.
