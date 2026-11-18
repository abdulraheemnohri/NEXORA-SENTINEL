# Project Status — NEXORA Sentinel

Last updated: 2026-11-18

## Current milestone
Safety kernel and governance foundation; implementation is incremental and the project is not yet complete.

## Completed and evidenced
- Fail-closed policy kernel, persistent emergency-stop marker and hash-chained local audit log.
- Capability catalogue entries 85–264 and meta-rules 16–45; original source ranges 1–84 and 1–15 are still missing.
- Evidence-gated lifecycle validator and safety-first precedence resolver.
- SQLite-backed capability lifecycle registry with transactional state/history writes and append-only transition events.
- Registry events record evidence and a human approver identifier for APPROVED/ENABLED transitions.
- GitHub Actions previously passed Ruff, pytest and compileall at commit 3df06c5165a29fe7ac05b2501a52dc24cfa36776.

## Current safety boundaries
- Registry stores governance metadata only; it never executes capability code.
- Unknown or equal-priority conflicts remain blocked for human review.
- Runtime policy mutation remains disabled.
- Keep PR #1 open; do not merge or publish a release without explicit user approval.
- A recorded approver identifier is an audit field, not cryptographic proof of identity.

## Remaining blockers and work
1. Validate the newest registry implementation in CI and fix any failures.
2. Add cryptographically verifiable approval receipts and revocation/rollback lifecycle semantics.
3. Recover the user's original capability definitions 1–84 and meta-rules 1–15; do not invent missing entries.
4. Implement registry migration/export/restore and corruption recovery tests.
5. Implement budgets, scheduler, sandbox and controlled tool boundaries after safety review.
6. Finish CLI/TUI/web interface, Android Debian validation, docs, threat-model audit and release workflow.

## Next task
Implement durable approval/revocation evidence with explicit separation between an operator-supplied identity label and a verifiable signed authorization.
