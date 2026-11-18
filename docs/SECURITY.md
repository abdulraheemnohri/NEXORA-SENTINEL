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
