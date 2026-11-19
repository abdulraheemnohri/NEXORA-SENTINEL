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

The existing lifecycle tables have SQLite update/delete triggers, but legacy
rows do not contain a cryptographic event hash chain. The report therefore
returns `history_authenticity=UNVERIFIED` and
`cryptographic_hash_chain=NOT_IMPLEMENTED_FOR_LEGACY_LIFECYCLE_EVENTS`.
A database owner or attacker able to rewrite the database file can bypass
SQLite triggers. Structural consistency is not proof of authenticity.

This release does not claim evidence expiry monitoring: current evidence
records do not define a canonical expiry contract. Missing, revoked or
outdated evidence cannot be reliably inferred without source-backed expiry
semantics. No automatic repair, promotion, rollback, policy change or execution
is performed.

A future cryptographic lifecycle ledger requires a separately reviewed,
versioned migration and an independently retained trust anchor. Existing
records must remain explicitly unverified; they must not be retroactively
attested.
