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
- Added an Ed25519 receipt module with explicit public-key pinning, scoped evidence digests, expiry, one-time nonce consumption and signer-key revocation.
- GitHub Actions previously passed Ruff, pytest and compileall at commit 3df06c5165a29fe7ac05b2501a52dc24cfa36776.

## Current safety boundaries
- Registry stores governance metadata only; it never executes capability code.
- Unknown or equal-priority conflicts remain blocked for human review.
- Runtime policy mutation remains disabled.
- Keep PR #1 open; do not merge or publish a release without explicit user approval.
- A recorded approver identifier is an audit field, not cryptographic proof of identity.
- Signed receipts prove possession of a locally pinned Ed25519 key only; trusted enrollment and operator identity verification remain a separate human process. The registry is not yet wired to require receipts.

## Remaining blockers and work
1. Validate the newest registry implementation in CI and fix any failures.
2. Integrate Ed25519 receipts as a mandatory gate for APPROVED/ENABLED registry transitions, with atomic replay consumption and migration tests. Registry transitions still accept operator labels pending this integration. Revocation is terminal; rollback entries are audit records only.
3. Recover the user's original capability definitions 1–84 and meta-rules 1–15; do not invent missing entries.
4. Implement registry migration/export/restore and corruption recovery tests.
5. Implement budgets, scheduler, sandbox and controlled tool boundaries after safety review.
6. Finish CLI/TUI/web interface, Android Debian validation, docs, threat-model audit and release workflow.

## Latest increment — 2026-11-18
- Added terminal capability revocation with required reason, evidence basis and operator label.
- Added append-only revocation and rollback event tables.
- Rollback recording requires a plan, validation report and operator approval label; it deliberately does not execute software rollback.
- Revoked capabilities cannot progress through the lifecycle again.
- Added regression tests for revocation, rollback evidence and evidence-input validation.
- Operator labels are audit metadata only, not cryptographic identity proof.

## Latest increment — 2026-11-18
- Added Ed25519 receipt creation and verification with canonical JSON signing.
- Receipts bind capability, transition, approver label, evidence digest, issue/expiry times, nonce and public-key fingerprint.
- Added explicit trust-key enrollment, signer-key revocation and persistent one-time nonce consumption in SQLite.
- Private-key helper creates a mode-0600 key file on POSIX and refuses overwrite by default. Keys are unencrypted at rest; protect the device account and back up securely.
- Added regression tests for valid receipts, tampering, untrusted keys, scope mismatch, expiry, evidence mismatch, replay, key revocation and key-file permissions.
- Important: registry transition enforcement is not yet connected to receipt verification; this is the cryptographic foundation, not a completed approval gate.

## Next task
Require valid signed receipts for APPROVED/ENABLED registry transitions, with atomic replay consumption and migration tests.
