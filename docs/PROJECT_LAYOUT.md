# Project layout and implementation status

This repository uses a responsibility-oriented package layout. Import facades are thin and delegate to tested implementations; they do not create parallel policy engines.

| Area | Responsibility | Current status |
|---|---|---|
| core | Agent state, lifecycle, planning and review scheduling | State/lifecycle and scheduler foundations exist; no autonomous loop |
| oversight | Policy kernel, audit, witness, kill switch, approvals and boundaries | Implemented locally; no remote hardware witness |
| governance | Interaction matrix, precedence, conflict and composition | Precedence resolver exists; matrix entries intentionally unknown |
| capabilities | Source catalogue, registry, maturity and family adapters | 180/264 source records; 26/40 canonical families represented |
| self_families | Observation, diagnostics, repair planning, learning, governance assistance and evolution proposal domains | Provisional, proposal-only domains; not canonical catalogue families |
| runtime | Staging, tool proposals and resource budgets | Review-only; no code/tool execution or OS sandbox |
| intelligence | Model selection, inference, reasoning and evaluation contracts | Interfaces and validation only; no model runtime |
| memory | Session notes, durable records, knowledge and provenance | Local storage contracts only; retrieval integration pending |
| evolution | Proposal, validation, shadow, canary and rollback gates | Safety gate contracts only; no self-modification execution |
| terminal | Command parsing, input sanitation and output checks | Defensive validation helpers |
| interfaces | CLI, TUI, local web and API | CLI works; TUI/web/API are explicit future deliverables |
| storage | SQLite connection, migrations and repositories | Existing SQLite modules; backup/restore and migration recovery implemented |

## Safety invariants

1. Unknown capability interactions are not assumed safe.
2. Proposal and approval are separate from execution.
3. Privilege expansion requires a signed, scoped, unexpired, one-time receipt.
4. The operator label is metadata; it is not identity proof.
5. Restore is validated and non-destructive.
6. Local SHA-256 manifests are not a substitute for signed external attestations.
7. Lifecycle state changes are eligibility/audit records, not execution commands.
8. Self-family proposals cannot execute, mutate policy or promote themselves.

## Source-of-truth rule

Where a package facade imports an existing module, the existing implementation remains authoritative. Future refactors must move behavior with tests and preserve backward-compatible imports until a separately reviewed migration is complete.
