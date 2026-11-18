# Project Status — NEXORA Sentinel

Last updated: 2026-11-18

## Current milestone

Safety kernel, modular package structure, signed SQLite backups, independent witness receipts, backup-first SQLite migration/recovery, provisional self-* domains, and durable append-only self-family proposal review records. The project is not complete.

## Implemented

- Fail-closed policy kernel, persistent emergency stop and hash-chained audit log.
- Evidence-gated lifecycle validator and safety-first precedence resolver.
- SQLite capability registry with append-only lifecycle, revocation and rollback-decision events.
- Ed25519 approval receipts for capability APPROVED/ENABLED transitions; nonce consumption and state mutation share a transaction.
- Persistent budget ledger, review-only scheduler and tool proposal queue.
- Safe staging workspace with path containment; staged code is not executed.
- WAL-safe SQLite online backup, signed canonical manifests and verification against an externally trusted public key.
- Verified non-overwriting restore and distinct-key Ed25519 witness receipts.
- Backup-first migration orchestration with all-or-nothing migration and separate recovery copy.
- Six provisional self-* domains with typed L0/L1 settings; execution and self-enablement remain disabled.
- SQLite self-family proposal storage with immutable proposal rows and append-only SUBMITTED/REVIEWED/REJECTED events.
- Review records are explicitly not cryptographic approvals or execution authorization.
- Conservative YAML settings profiles, modular package structure and TLA+ lifecycle model.

## Explicitly incomplete

- Canonical capability source records 1–84 and meta-rules 1–15 have not been supplied.
- The 264×264 interaction matrix remains unpopulated/unknown; unknown relationships block.
- TUI, web dashboard and API are not shipped as usable interfaces.
- Model runtime/inference are disabled; local model inventory is read-only.
- Memory retrieval and knowledge graph integration remain limited foundations.
- Staging is not an OS-enforced sandbox; no tool or staged-code execution is enabled.
- Self-* domains do not perform autonomous self-repair, self-learning or self-evolution.
- Operator labels do not prove identity.
- Witness receipts remain local unless independently hosted; no hardware/remote attestation is claimed.
- Multi-process witness append locking is not implemented.
- Android Debian/Pixel device verification has not been performed.

## Next priorities

1. Read-only TUI and local dashboard before execution controls.
2. Obtain the missing canonical capability and meta-rule source records.
3. Populate interaction relationships only from reviewed source specifications.
4. Design OS-enforced sandbox isolation before considering code execution.
5. Verify installation and behavior on Android Debian/Pixel locally.
6. Expand migration drills against supported release history.

PRs and releases remain subject to explicit owner approval.
