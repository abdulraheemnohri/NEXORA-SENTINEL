# Project Status — NEXORA Sentinel

Last updated: 2026-11-18

## Current milestone

Safety kernel, modular package layout and durable local platform foundations. The project is not complete.

## Implemented and CI-covered

- Fail-closed policy kernel, emergency stop and hash-chained audit log.
- Evidence-gated sequential lifecycle validator and safety-first precedence resolver.
- SQLite capability registry with append-only lifecycle, revocation and rollback-decision events.
- Ed25519 approval receipts; APPROVED and ENABLED require scoped signed receipts. Receipt nonce consumption and lifecycle mutation share one SQLite transaction.
- Persistent budget ledger, review-only scheduler and tool proposal queue.
- Safe staging workspace with path containment; submitted code is not executed.
- SQLite online backup, SHA-256 manifest verification and non-overwriting restore.
- Local settings, read-only diagnostics, modular package import surfaces and CLI.
- Tests, documentation and GitHub CI.

## Explicitly incomplete

- Capability source records 1–84 and meta-rules 1–15 have not been supplied.
- Interaction matrix dimensions are 264×264 but entries remain unknown/empty.
- TUI, web dashboard and API are not implemented.
- Model runtime, production memory retrieval and self-evolution execution are not implemented.
- Staging is not an OS-level sandbox; no tool execution is enabled.
- Operator labels are not cryptographic identity proof.
- Local backup manifests are unsigned; SHA-256 alone is not authenticated provenance.
- Android Debian/Pixel device testing has not been performed remotely.

## Next priorities

1. Verify CI for the modular package and backup/restore milestone.
2. Add backup signing and external witness verification.
3. Complete read-only TUI and dashboard before any execution features.
4. Add migration/version tests and formal state-machine checks.
5. Recover missing original source specifications from the project owner.
6. Conduct Android Debian installation and device verification locally.

PR #1 remains open and unmerged. Do not merge or release without explicit owner approval.
