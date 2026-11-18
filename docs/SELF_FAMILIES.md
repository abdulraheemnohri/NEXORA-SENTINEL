# Provisional self-* operational domains

The six domains in `nexora.self_families` are provisional operational groupings,
not canonical A–AN source families. They must not be used to fill missing source
records or invent capability relationships.

## Domains

- `self_observation`: bounded, read-only state snapshots.
- `self_diagnostics`: evidence-backed findings and uncertainty.
- `self_repair_planning`: reversible repair proposals only.
- `self_learning`: provenance-linked untrusted knowledge candidates.
- `self_governance_assistance`: policy conflict explanations; kernel remains authoritative.
- `self_evolution`: staged change proposals; promotion remains disabled.

## Durable proposal records

`SelfFamilyProposalStore` stores deterministic proposal IDs, family, summary,
evidence references and payload digest in SQLite. Proposal rows are immutable.
Submission and review decisions are append-only events in the same database.
The supported human review outcomes are `REVIEWED` and `REJECTED`.

**A review outcome is not a cryptographic approval.** Operator labels are
descriptive labels, not identity proof. This store does not authorize lifecycle
promotion, modify policy, execute tools, run staged code, or enable a family.
Every stored proposal has `execution=DISABLED`. A separate, scoped signed
approval protocol is required before any future staging or lifecycle action.

The store uses SQLite WAL mode and `synchronous=FULL`; keep backups and trusted
keys under separate access controls. Local SQLite triggers deter accidental
mutation but are not tamper-proof against an attacker able to replace the DB.
