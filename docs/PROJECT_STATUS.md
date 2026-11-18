# Project Status — NEXORA Sentinel

Last updated: 2026-11-18

## Current milestone

Safety kernel, modular package structure, local platform foundations, signed SQLite backups and cryptographic witness receipts. The project is not complete.

## Implemented before this milestone

- Fail-closed policy kernel, persistent emergency stop and hash-chained audit log.
- Evidence-gated sequential lifecycle validator and safety-first precedence resolver.
- SQLite capability registry with append-only lifecycle, revocation and rollback-decision events.
- Ed25519 approval receipts; APPROVED and ENABLED require scoped signed receipts. Receipt nonce consumption and lifecycle mutation share one SQLite transaction.
- Persistent budget ledger, review-only scheduler and tool proposal queue.
- Safe staging workspace with path containment; submitted code is not executed.
- Conservative YAML settings profiles and validated YAML loader.
- Modular packages for core, oversight, governance, capabilities, runtime, intelligence, memory, evolution, terminal, interfaces and storage.
- SQLite migration runner, local memory records, provenance helpers and proposal-only evolution gates.
- Formal TLA+ lifecycle model and GitHub Actions verification workflows.

## New security increment — pending CI

- Backup manifests use Ed25519 signatures over canonical manifest content.
- Backup verification requires an externally supplied trusted public key; embedded manifest key claims are not trusted.
- Backup private/public key generation refuses overwrite and applies restrictive private-key permissions.
- Restore verifies signature, content digest, SQLite integrity and schema metadata before non-overwriting publication.
- Independent witness receipts use a separate Ed25519 key and a sequence-linked hash chain.
- Witness-chain verification checks every signature, signer fingerprint, sequence and previous-receipt link.
- The witness remains local unless independently hosted; no hardware or remote attestation is claimed.
- Multi-process witness append locking is not implemented.

## Verification status

The previous branch head 1009891b75cac46e93bdc40bc52d36525035f360 passed Ruff, 54 pytest tests, compileall, dependency checks, build and TLC. The new signed-backup increment has not yet completed CI; do not treat it as verified until the latest GitHub Actions runs pass.

## Explicitly incomplete

- Capability source records 1–84 and meta-rules 1–15 have not been supplied.
- Interaction matrix dimensions are 264×264 but entries remain unknown/empty.
- TUI, web dashboard and API are namespace surfaces only; no interactive UI/server is shipped.
- Model runtime and inference are disabled; local model inventory is read-only.
- Memory retrieval and knowledge graph integration remain limited foundations.
- Staging is not an OS-level sandbox; no tool execution is enabled.
- Operator labels are not cryptographic identity proof.
- Local audit and witness files can be rewritten by an attacker with sufficient filesystem privileges; external copies and independently controlled keys are required for stronger assurance.
- Android Debian/Pixel device testing has not been performed remotely.

## Next priorities

1. Validate signed backup and witness features across tampering, key rotation, restore and recovery scenarios.
2. Add migration compatibility and restore drills across schema versions.
3. Build a read-only TUI and local dashboard before any execution controls.
4. Complete source-backed capability and meta-rule definitions from the project owner.
5. Populate interaction-matrix relationships only from reviewed source specifications.
6. Design OS-enforced sandbox isolation before considering code execution.
7. Conduct Android Debian installation and device verification locally.

PR #1 remains open and unmerged. Do not merge or release without explicit owner approval.
