# API and package map

This release exposes a Python package and CLI. Stable public import surfaces include:

- `nexora.core`: proposal planning and lifecycle APIs.
- `nexora.oversight`: policy, audit, kill switch, witness and approval gateway.
- `nexora.governance`: precedence and unknown-safe interaction lookup.
- `nexora.capabilities`: immutable source records and persistent registry.
- `nexora.runtime`: staging, resource budgets and proposal-only tool bus.
- `nexora.intelligence`: local model inventory and output evaluation contracts.
- `nexora.memory`: bounded session memory, SQLite records and provenance.
- `nexora.evolution`: proposal, validation, shadow and canary gates.
- `nexora.terminal`: restricted command parsing and output sanitation.

CLI commands: `status`, `catalog-check`, `check`, `audit`, `kill`, `resume`, `registry-init`, `backup`, `verify-backup`, `restore`.

Backup workflow: initialize the registry with `nexora registry-init`, create a snapshot with `nexora backup`, verify it with `nexora verify-backup PATH`, and restore to a new destination with `nexora restore BACKUP DESTINATION`.

No interactive HTTP control API or runtime execution API is enabled. The local web server exposes loopback-only, GET-only diagnostic views; it has no mutation or execution endpoints.


## Capability maturity report

- `GET /api/maturity-report`: source-backed capability maturity and evidence report.
- `GET /api/maturity-report?capability_id=85`: one source-backed capability.
- The report uses the existing lifecycle evidence gates. L0-L4 remains
  `UNDEFINED_SOURCE_GAP` until canonical definitions and thresholds are supplied.
- The endpoint is read-only and does not promote capabilities or enable execution.


## Lifecycle history and regression diagnostics

- `GET /api/lifecycle-history`: read-only structural replay of lifecycle, revocation and rollback events.
- `GET /api/lifecycle-history?capability_id=85`: filter to one capability ID (1–264).
- CLI: `nexora lifecycle-history` and `nexora regression-report`, with optional `--capability-id` and `--database`.
- The report detects state/history divergence and malformed transition sequences. Legacy lifecycle history has no cryptographic event chain, so authenticity is explicitly `UNVERIFIED`.
- No lifecycle mutation, promotion, rollback execution, or tool execution is possible through these reports.
