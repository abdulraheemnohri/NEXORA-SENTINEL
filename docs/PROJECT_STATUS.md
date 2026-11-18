# Project Status — NEXORA Sentinel

Last updated: 2026-11-18

## Current milestone
Safety kernel and local platform foundations. The project is not complete.

## Implemented
- Fail-closed policy kernel, emergency stop and hash-chained audit log.
- Capability lifecycle validator and safety-first precedence resolver.
- SQLite capability registry, append-only lifecycle events, terminal revocation and rollback decision records.
- Ed25519 receipt creation, explicit trust enrollment, key revocation, expiry and nonce replay protection.
- Persistent resource budget ledger.
- Persistent scheduler that only claims due jobs; it does not execute them.
- Tool proposal queue; no tool implementation is invoked.
- Safe staging workspace with path containment; no code execution.
- Local config validation and read-only diagnostics.
- Expanded test suite and project documentation/layout.

## CI repair
The newest Ed25519 commit failed Ruff because one local import block was not sorted. The import ordering has been corrected in the project-structure increment. The updated CI run must confirm Ruff, pytest and compileall before this increment is marked verified.

## Specification blockers
- Capabilities 1–84: original source definitions not supplied.
- Meta-rules 1–15: original source definitions not supplied.
- Interaction matrix: all relations remain unknown/unpopulated.
- Expected totals: 264 capabilities, 40 canonical families, 45 meta-rules.

## Security boundaries
- No autonomous tool execution, model runtime or self-modification.
- Scheduler is a durable review queue, not an executor.
- Tool boundary stores proposals only.
- Staging workspace does not execute code and is not an OS-level sandbox.
- Signed receipts prove possession of a pinned key, not human identity.
- Registry APPROVED/ENABLED transitions are not yet cryptographically receipt-gated.
- Operator labels remain audit metadata.
- PR #1 remains open; do not merge or release without explicit user approval.

## Next priorities
1. Verify current CI and fix every reported failure.
2. Integrate signed receipt verification atomically into registry APPROVED/ENABLED transitions.
3. Add safe registry backup/export/restore and migration tests.
4. Recover missing original specification ranges from the user; do not invent them.
5. Continue reviewed sandbox, scheduler, budgets, TUI/web UI and model integration design.
6. Perform Android Debian/Pixel testing; not yet performed by this remote GitHub work.


## Signed approval enforcement update
- APPROVED and ENABLED transitions now require a valid Ed25519 receipt.
- Receipt verification and nonce consumption use the same SQLite connection and transaction as the lifecycle state update.
- A failed lifecycle transition rolls back receipt consumption; regression tests cover this atomicity.
- Existing unsigned registry transition calls for APPROVED/ENABLED are intentionally rejected.
