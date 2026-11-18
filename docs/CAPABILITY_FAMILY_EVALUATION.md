# Capability family evaluation

The family evaluator is a read-only aggregation over the exact source-backed
capability catalogue and the local evidence ledger. It does not create
capability definitions, dependency edges, pairwise relations, approvals, or
lifecycle transitions.

## CLI

    nexora family-evaluation
    nexora family-evaluation --family O
    nexora family-evaluation --database data/registry.sqlite3

The family filter accepts only canonical family codes A–AN (40 families),
or CROSS-CUTTING when present in the source catalogue. Unknown family filters
fail with an explicit error rather than returning an empty, misleading report.

## Dashboard

The loopback-only GET endpoint is:

    GET /api/family-evaluation
    GET /api/family-evaluation?family=O

## Interpretation

- NOT_EVALUATED_NO_LEDGER: no local evidence database was found.
- BLOCKED_LEDGER_INTEGRITY: the evidence ledger failed verification.
- EVIDENCE_GAPS: at least one source-backed capability has a missing evidence
  token.
- EVIDENCE_PRESENT_AWAITING_HUMAN_AUTHORIZATION: all required evidence tokens
  are present for every capability in the family, but the existing separate
  human-authorization gate remains closed.
- EVIDENCE_COMPLETE: reserved for a future trusted authorization-aware
  evaluator; this report does not supply human approval.
- SOURCE_DEFINITIONS_NOT_PRESENT: the canonical family is displayed, but no
  source-backed capability records for it exist in the current catalogue.

All 40 canonical family codes are displayed, including families without
source-backed records. A missing family name is reported as null rather than
invented. The global catalogue summary separately reports missing capability
IDs; it does not guess which family owns a missing ID.

Catalogue status counts (such as specified) are reported separately from
evidence assessment. Missing definitions 1–84 remain explicit source gaps.
The evaluator does not infer dependencies or interactions from family
membership or IDs.

All output is diagnostic only: lifecycle changes, promotions, policy mutation,
and execution are disabled.
