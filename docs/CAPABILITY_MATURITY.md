# Capability maturity and evidence intelligence

Run a read-only report:

```sh
nexora maturity-report
nexora maturity-report --capability-id 85
nexora maturity-report --database data/registry.sqlite3
```

The report combines the source-backed catalogue with the existing append-only,
hash-chained evidence ledger and the exact lifecycle evidence requirements.
A corrupt ledger blocks evidence assessment. A missing ledger is reported as
not evaluated. The report does not fetch, inspect, or prove external artifacts.

## L0-L4 is intentionally unassigned

The canonical L0-L4 definitions and evidence thresholds are not present in the
repository source material currently available. Therefore every capability
reports `UNDEFINED_SOURCE_GAP`, with no assigned level. The report does not
map lifecycle states to L0-L4 and does not invent criteria.

## Regression and promotion limits

Trusted append-only lifecycle transition history is not yet available to this
report, so regression detection is explicitly unavailable. Evidence readiness
is diagnostic only. Any future promotion recommendation must remain a human
review proposal. This report never changes lifecycle state, policy, or execution
permissions.
