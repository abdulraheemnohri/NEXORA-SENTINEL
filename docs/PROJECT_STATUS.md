# Project Status — NEXORA Sentinel

Last updated: 2026-11-18

## Current milestone

Safety kernel, modular package structure, local platform foundations, signed SQLite backups, independent witness receipts, and backup-first SQLite migration/recovery orchestration. The project is not complete.

## Implemented and CI-verified

- Fail-closed policy kernel, persistent emergency stop and hash-chained audit log.
- Evidence-gated sequential lifecycle validator and safety-first precedence resolver.
- SQLite capability registry with append-only lifecycle, revocation and rollback-decision events.
- Ed25519 approval receipts; APPROVED and ENABLED require scoped signed receipts. Receipt nonce consumption and lifecycle mutation share one SQLite transaction.
- Persistent budget ledger, review-only scheduler and tool proposal queue.
- Safe staging workspace with path containment; submitted code is not executed.
- SQLite online backup using WAL-safe snapshot API.
- Ed25519-signed canonical backup manifests; verification requires an independently trusted public key.
- Backup key generation refuses overwrite and protects private-key file permissions.
- Restore verifies signature, SHA-256, SQLite integrity and schema metadata before non-overwriting publication.
- Independent witness receipts use a distinct Ed25519 signing key and sequence-linked hash chain.
- Witness verification checks signatures, signer fingerprint, sequence and previous-receipt linkage.
- Backup-first migration orchestration: verified backup, all-or-nothing migration transaction, integrity checks and recovery copy to a separate path.
- Migration runner rejects missing versions, invalid registries, newer database schemas and caller-owned transactions.
- Conservative YAML settings profiles and validated YAML loader.
- Modular packages for core, oversight, governance, capabilities, runtime, intelligence, memory, evolution, terminal, interfaces and storage.
- Formal TLA+ lifecycle model and GitHub Actions verification workflows.

## Explicitly incomplete

- Capability source records 1–84 and meta-rules 1–15 have not been supplied.
- Interaction matrix dimensions are 264×264 but entries remain unknown/empty.
- TUI, web dashboard and API are namespace surfaces only; no interactive UI/server is shipped.
- Model runtime and inference are disabled; local model inventory is read-only.
- Memory retrieval and knowledge graph integration remain limited foundations.
- Staging is not an OS-level sandbox; no tool execution is enabled.
- Operator labels are not cryptographic identity proof.
- Witness receipts remain local unless the witness process/key is independently hosted. No hardware or remote attestation is claimed.
- Multi-process witness append locking is not implemented.
- Local audit and witness files can be rewritten by an attacker with sufficient filesystem privileges; retain external evidence copies and independently controlled trust keys.
- Android Debian/Pixel device testing has not been performed remotely.

## Next priorities

1. Read-only TUI and local dashboard before any execution controls.
2. Complete source-backed capability and meta-rule definitions from the project owner.
3. Populate interaction-matrix relationships only from reviewed source specifications.
4. Design OS-enforced sandbox isolation before considering code execution.
5. Conduct Android Debian installation and device verification locally.
6. Expand migration drills against the real registry schema and supported release history.

PRs and releases remain subject to explicit owner approval.
