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

## Cryptographic lifecycle chain

- The registry initializes a SHA-256 event chain for newly created lifecycle, revocation and rollback records.
- Legacy event IDs are captured as activation watermarks and are never retroactively attested.
- The activation watermarks are bound into the chain genesis hash.
- `nexora lifecycle-chain-attest --witness-key PRIVATE --witness-log PATH --confirm` appends a signed external checkpoint.
- `nexora lifecycle-chain-verify --witness-log PATH --trusted-witness-key PUBLIC` verifies the chain and requires the latest witness receipt to match its current head.
- The external witness key and log must be held separately from the registry database to provide an independent trust anchor.


## Evidence freshness intelligence

- Evidence ledger schema v3 supports optional timezone-aware `expires_at` metadata, included in each new record's canonical hash.
- Add evidence with `nexora evidence add ... --expires-at 2027-01-01T00:00:00Z --confirm`.
- CLI report: `nexora evidence freshness [--capability-id 85]`.
- Web: `GET /api/evidence-freshness` and optional `?capability_id=85`.
- Terminal dashboard option 5 displays the read-only summary.
- `UNKNOWN` is the correct status when no operator expiry is declared. `CURRENT` and `EXPIRED` are determined only from an explicit expiry timestamp; failed ledger integrity yields `UNVERIFIED`.
- This report does not infer missing evidence, invalidate records, alter lifecycle state, authorize actions, or execute tools. See [Evidence Freshness](EVIDENCE_FRESHNESS.md).


## Evidence provenance intelligence

- Evidence ledger schema v4 optionally records `source_uri`, `source_revision`, and timezone-aware `collected_at`, all bound into the evidence record hash.
- Create evidence with `--source-uri`, `--source-revision`, and optional `--collected-at`.
- CLI report: `nexora evidence provenance [--capability-id 85] [--limit 500]`.
- Web: `GET /api/evidence-provenance` and optional `?capability_id=85`.
- Terminal dashboard option 6 displays the read-only provenance summary.
- Status labels describe declared metadata completeness only; they do not independently authenticate the source, resolve revisions, or detect upstream changes.
- Legacy records remain unchanged and are reported as UNDECLARED.
- See [Evidence Freshness and Provenance](EVIDENCE_FRESHNESS.md).


## Settings dashboard

- `GET /api/settings`: displays the validated local settings file (`config/settings.yaml` by default) or safe built-in defaults when the file is absent.
- The root dashboard includes a responsive Settings and Safety Controls panel. Invalid, unreadable, symlinked or unsupported settings files are reported as invalid and fail closed.
- The panel is read-only. It exposes no settings write, apply, policy mutation, scheduler enablement, sandbox enablement or network enablement action. Use `nexora settings diff` for a separate candidate preview; authorization remains `NOT_EVALUATED`.


## Specification readiness

- CLI: `nexora spec-status` aggregates exact-source capability/meta-rule
  coverage, matrix coverage, precedence integrity and settings authorization
  readiness.
- CLI: `nexora settings policy-status` reports settings without an approved
  per-setting authorization and rollback policy.
- Both reports are read-only. A present policy file is not treated as approved.
- Missing source records and unknown matrix relationships remain blockers.
- No settings apply or execution endpoint is exposed.
- See [SPECIFICATION_READINESS.md](SPECIFICATION_READINESS.md).


## Specification readiness APIs

- `GET /api/spec-status`: read-only aggregate of canonical source coverage,
  catalogue integrity, interaction-matrix coverage, precedence validity and
  settings-policy readiness.
- `GET /api/settings-policy`: reports whether a reviewed per-setting
  authorization and rollback policy exists. A file's presence is not approval.
- Both endpoints expose `read_only: true`; neither grants settings mutation,
  policy mutation, capability activation or execution.
