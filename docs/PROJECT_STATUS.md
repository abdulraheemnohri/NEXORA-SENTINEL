# Project Status — NEXORA Sentinel

Last updated: 2026-11-18

## Current milestone

Safety kernel, modular package structure, local platform foundations, signed SQLite backups and cryptographic witness receipts. The project is not complete.

## Implemented and CI-verified

- Fail-closed policy kernel, persistent emergency stop and hash-chained audit log.
- Evidence-gated sequential lifecycle validator and safety-first precedence resolver.
- SQLite capability registry with append-only lifecycle, revocation and rollback-decision events.
- Ed25519 approval receipts; APPROVED and ENABLED require scoped signed receipts. Receipt nonce consumption and lifecycle mutation share one SQLite transaction.
- Persistent budget ledger, review-only scheduler and tool proposal queue.
- Safe staging workspace with path containment; submitted code is not executed.
- SQLite online backup using WAL-safe snapshot API.
- Ed25519-signed canonical backup manifests; verification requires a trusted public key supplied independently of the backup.
- Backup key generation refuses overwrite and protects private-key file permissions.
- Restore verifies signature, SHA-256, SQLite integrity and schema metadata before non-overwriting publication.
- Independent witness receipts use a distinct Ed25519 signing key and sequence-linked hash chain.
- Witness verification checks signatures, signer fingerprint, sequence and previous-receipt linkage.
- CLI rejects reusing the backup signing key as the witness key.
- Conservative YAML settings profiles and validated YAML loader.
- Modular packages for core, oversight, governance, capabilities, runtime, intelligence, memory, evolution, terminal, interfaces and storage.
- SQLite migration runner, local memory records, provenance helpers and proposal-only evolution gates.
- Formal TLA+ lifecycle model and GitHub Actions verification workflows.

## Latest verification — commit ef4d1b9060a79815c02f83bbfedb9a45754f8e7e

All five workflows passed on GitHub-hosted Linux / Python 3.12.16:

- Tests: 61 passed.
- Ruff: passed.
- Python compileall: passed.
- Dependency consistency (pip check): passed.
- Build wheel: passed.
- TLA+ formal lifecycle verification: passed.
- Security workflow: passed.

This is hosted CI evidence, not Android Debian or Pixel 6 device testing.

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

1. Migration compatibility and restore drills across schema versions.
2. A read-only TUI and local dashboard before any execution controls.
3. Complete source-backed capability and meta-rule definitions from the project owner.
4. Populate interaction-matrix relationships only from reviewed source specifications.
5. Design OS-enforced sandbox isolation before considering code execution.
6. Conduct Android Debian installation and device verification locally.

PR #1 remains open and unmerged. Do not merge or release without explicit owner approval.
