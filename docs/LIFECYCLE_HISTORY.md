# Lifecycle History & Regression Diagnostics

NEXORA reuses the existing SQLite `lifecycle_events`, `revocation_events`,
and `rollback_events` tables. This feature does not introduce a parallel event
store or mutate lifecycle state.

## Commands

```bash
nexora lifecycle-history
nexora lifecycle-history --capability-id 85
nexora regression-report
```

Both commands are read-only. They require an existing `registry.sqlite3` and
open it in SQLite read-only/query-only mode. They never initialize storage.

## What is checked

- The initial SPECIFIED event exists and has no previous state.
- Each later event's previous state matches the prior replayed state.
- Transitions are sequential according to the existing lifecycle ordering.
- Replayed state matches the current capability row.
- Revoked control state has a revocation event; active state has none.
- Multiple revocation events are flagged.
- Rollback authorization history is counted but is not interpreted as a
  deployed rollback or a lifecycle transition.

## Trust boundary

New lifecycle, revocation and rollback events are included in the SHA-256 chain
implemented in `docs/LIFECYCLE_CHAIN.md`. The history report verifies that chain
and distinguishes `STRUCTURALLY_CONSISTENT`, `CHAIN_NOT_MIGRATED`,
`CHAIN_INTEGRITY_FAILED` and `REGRESSION_DETECTED`.

Existing records at chain activation watermarks remain explicitly unverified.
The report never retroactively hashes or attests them. A local chain is not an
independent trust anchor: a privileged database owner can rewrite local data.
Use the separate Ed25519 witness checkpoint workflow to anchor the current
chain head outside the registry database.

This release does not claim evidence expiry monitoring: current evidence
records do not define a canonical expiry contract. Missing, revoked or
outdated evidence cannot be reliably inferred without source-backed expiry
semantics. No automatic repair, promotion, rollback, policy change or execution
is performed.

The chain does not define evidence expiry or freshness semantics. Those remain
blocked until canonical source-backed expiry rules are provided. No automatic
repair, promotion, rollback, policy change or execution is performed.
