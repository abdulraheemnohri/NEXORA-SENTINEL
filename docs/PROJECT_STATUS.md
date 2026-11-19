# Project Status — NEXORA Sentinel

Last updated: 2026-11-19

## Current milestone

Safety kernel, durable self-family proposal review, capability evidence/maturity reporting, artifact integrity verification, cryptographic lifecycle event chaining, independent witness checkpoints, lifecycle-history regression diagnostics, and read-only terminal/web dashboards. This is still a governance/runtime foundation, not a completed autonomous agent.

## Implemented

- Fail-closed policy kernel, persistent emergency stop and hash-chained audit log.
- Evidence-gated lifecycle registry, signed Ed25519 approvals, append-only lifecycle/revocation/rollback records.
- Persistent budget ledger, review-only scheduler and tool proposal queue.
- WAL-safe signed SQLite backups, external trust-key verification, non-overwriting restore, independent witness receipts.
- Backup-first transactional migrations and recovery-copy workflow.
- Six provisional self-* domains; typed L0/L1 settings, deterministic proposals and durable append-only review records.
- Read-only terminal dashboard: overview, audit chain, proposals and capability registry. SQLite dashboard views open the database in read-only mode and do not initialize or mutate it.
- Read-only capability family evaluator: aggregates source-backed family membership, catalogue status, and verified evidence-ledger coverage; distinguishes missing evidence from evidence awaiting human authorization; exposes a CLI and GET-only dashboard endpoint without lifecycle promotion.
- Loopback-only GET web dashboard and JSON diagnostic endpoints; Host header is checked, mutation methods are rejected, and the server binds only to 127.0.0.1.
- Conservative YAML profiles, modular package structure and TLA+ lifecycle model.
- Built-in GitHub updater: checks the official main-branch commit, previews changed paths, summarizes Actions runs for the exact target SHA, and blocks installation on a known failed CI run. Explicit installation still requires confirmation, official origin, main branch, clean worktree and fast-forward-only history. It reinstalls the local package and attempts source rollback if installation fails. Separate Ed25519 update-manifest signing and verification commands bind repository/ref/commit/version and require an externally supplied trusted public key; a dedicated update-key generator creates non-overwriting key files with restrictive private-key permissions.
- New lifecycle, revocation and rollback events are appended to a SHA-256 chain in the same SQLite transaction; the verifier checks event order, source-row equality, chain continuity and post-activation coverage. Legacy event IDs are preserved as unverified watermarks bound into the chain genesis.
- Operator-driven Ed25519 lifecycle-chain checkpoints use the existing independent witness receipt format. Verification requires the latest signed checkpoint to match the current chain head; witness key/log storage must be separate from the registry. A local chain without an external checkpoint is not an independent trust anchor.
- Read-only lifecycle history and regression diagnostics replay existing lifecycle/revocation/rollback events and expose CLI plus GET-only dashboard output.
- Read-only settings inspection and validation CLI: missing files use safe L0 defaults; existing invalid files and unknown keys fail closed; no settings mutation or execution toggles are exposed.
- Durable explicit-write memory store with SHA-256 source fingerprints, deterministic AND-term retrieval, append-only record/event tables, tombstone deletion and legacy-store import; read-only search does not create missing storage.

## Explicitly incomplete

- Canonical capability source records 1–84 and meta-rules 1–15 have not been supplied.
- The 264×264 interaction matrix remains unknown/unpopulated.
- Interactive API/control plane is not shipped; the local web dashboard is read-only diagnostics only, including the new Runtime & Models page.
- LiteRT-LM integration is implemented as an optional managed CLI adapter with local `.litertlm` inventory and a gated Hugging Face repository import path (including `litert-community/Qwen3-4B-Thinking-2507`). Network downloads require a settings opt-in plus per-command confirmation; inference requires separate opt-in/confirmation. CPU is default, subprocesses are bounded and shell-free, Python presets and model-provided tools remain disabled. The broader autonomous agent inference/tool loop remains disabled. Trusted memory supports explicit local writes and deterministic provenance-verified lexical retrieval; no semantic/embedding retrieval or model-originated writes.
- Staging is not an OS-enforced sandbox; no tool or code execution is enabled.
- Self-* domains do not autonomously repair, learn into trusted memory, or evolve.
- Operator labels do not prove identity; local witness is not remote attestation.
- Android Debian/Pixel LiteRT-LM package, Hugging Face model download, model-load, CPU and GPU verification has not been performed. The requested Qwen3 4B model bundle is roughly 2.5 GB; device memory/storage suitability must be measured on target hardware.

## Next priorities

1. Qualify lifecycle chain and witness checkpoint backup/recovery procedures, and test cross-device external witness storage.
2. Define source-backed evidence expiry/revocation semantics before implementing evidence freshness monitoring.
3. Add a controlled, audited settings-change workflow only after defining per-setting authorization and rollback requirements.
4. Test read-only dashboard and CLI behavior on supported Linux and Android Debian terminals.
5. Obtain missing source-backed capability/meta-rule definitions and reviewed interaction relationships.
6. Design OS-enforced sandbox isolation before any execution feature.
7. Verify the official LiteRT-LM CLI and a small `.litertlm` model on Pixel/Android Debian; only then test Qwen3-4B-Thinking-2507 with measured resource/throughput results.

No merge or release is performed without owner approval.


## Update trust gate

The updater install path now requires a signed Ed25519 manifest verified against a separately provisioned public key, exact commit-SHA equality with GitHub main, successful exact-SHA CI, a clean worktree and fast-forward ancestry. No publisher key is embedded or assumed. A release signing workflow and independently distributed publisher key remain operator/release-process tasks.


## Evidence Freshness Intelligence v1

Implemented in the current development line:

- Evidence ledger schema v3 stores optional timezone-aware operator-declared `expires_at` metadata inside the record hash.
- Legacy schema v1/v2 evidence hashes are preserved; records without expiry remain UNKNOWN.
- Read-only freshness report distinguishes CURRENT, EXPIRED, UNKNOWN, UNVERIFIED and INVALID_METADATA.
- CLI, loopback web dashboard API and terminal dashboard expose the report.
- Reports disclose the 500-record display bound and whether coverage is complete.
- No canonical expiry policy is embedded; no freshness is inferred from creation time or evidence type.
- No automatic evidence invalidation, deletion, lifecycle transition, authorization or execution.

Verification status is determined by the exact-SHA GitHub Actions runs. See [EVIDENCE_FRESHNESS.md](EVIDENCE_FRESHNESS.md) for operator usage and limitations.


## Evidence Provenance Intelligence v2

Implemented in the current development line:

- Evidence ledger schema v4 stores optional source URI, source revision and collection timestamp fields in the record hash.
- Legacy evidence versions retain their original hash representation; missing provenance remains UNDECLARED.
- Read-only provenance inventory distinguishes DECLARED_COMPLETE, DECLARED_PARTIAL, UNDECLARED and UNVERIFIED.
- CLI, loopback web dashboard API and terminal dashboard expose the report.
- Operator declarations are not independent source authentication; remote revision resolution and change detection are not implemented.
- No evidence mutation, lifecycle transition, authorization or execution is performed by the report.

Exact-SHA workflow status must be checked before treating this milestone as verified. See [EVIDENCE_FRESHNESS.md](EVIDENCE_FRESHNESS.md).

## Atomic settings persistence hardening — 2026-11-19

- `Settings.save()` now serializes before touching the destination, writes a same-directory temporary file, applies owner-only POSIX permissions where supported, flushes and fsyncs file contents, atomically replaces the target, and fsyncs the containing directory on POSIX.
- Rejects symlink destinations (including dangling links) and existing non-file targets. Temporary files are cleaned after write/replace failures; a failed replacement preserves the previous settings file.
- Added regression tests for successful replacement/round-trip, replacement failure preserving the old file, temporary-file cleanup, symlink refusal, directory refusal, and POSIX mode 0600.
- Added `docs/SETTINGS_PERSISTENCE_SAFETY.md`. This does not add a settings editor or policy mutation surface; settings inspection remains read-only, L0 remains default, and scheduler/sandbox/network remain disabled by default.
- Commits: implementation `0fc0f71236af98eb0ed5585eca4aa86607f81051`; tests `173b2fb25362e27f7038453f83b85c71d7ce78ab`; documentation `c9e0b68b47700403527ab0501f579285e6864752`.
- Persistence-only verification at commit `f1d2649b2e41c9b0678a339fc3ffcfa43c6a11e9`: all five workflows passed (CI, Tests, Security, Build and Formal Verification). GitHub-hosted Linux executed Ruff, pytest, compileall, pip check, wheel build and TLC. This does not validate the later settings-diff preview changes below.

### Next task

After all exact-SHA workflows pass, define the reviewed per-setting authorization and rollback requirements before implementing a controlled settings-change workflow. Do not expose settings mutation until those governance rules are approved.

## Settings change preview and path hardening — 2026-11-19

- Added `nexora settings diff --config CURRENT --candidate PROPOSED`, a read-only comparison of validated settings files.
- Changed settings return `REVIEW_REQUIRED`, `authorization=NOT_EVALUATED`, and `apply_supported=false`; identical settings return `NO_CHANGES`. The CLI returns exit code 3 for a non-empty diff and never writes either file.
- No per-setting authorization matrix is assumed or fabricated. There is no settings apply command, policy mutation, feature enablement or autonomy increase.
- Settings inspection now uses `lstat()` and rejects symlink paths, including dangling symlinks, instead of treating an uninspectable/dangling path as absent defaults. Candidate settings use the same strict loader.
- Added tests for diff output, no-change behavior, invalid/missing candidate files, CLI non-mutation, and symlink rejection.
- README and `docs/SETTINGS_PERSISTENCE_SAFETY.md` document the preview-only contract.
- Current branch-head verification is pending after these additions; do not infer it from the earlier persistence-only run.


### Validation correction

The first workflow run for the settings-diff increment caught four Ruff F821 errors because the new tests had not imported `Settings` (run `44454809809`). The explicit import was added in commit `0d2d8ccec3b5dd591330f47bd9fac2a27a326240`. All five workflows then passed on that code/test commit: CI `44454875472`, Tests `44454875493`, Security `44454875533`, Build `44454875513`, and Formal Verification `44454875517`. CI/Tests/Security each report Ruff passed, compileall passed, and 346 pytest tests passed; Security also reports `pip check` passed. Build reports wheel creation passed; TLC model check passed. The only later commit is this documentation update (`902092e076ee7850870cff1e9219750e30fb3b5f`).


## Final testing preparation increment — 2026-11-19

- Added `.github/workflows/platform-qualification.yml` with Ubuntu and Windows hosted runners on Python 3.11 and 3.12. Each job runs dependency consistency, Ruff, the full pytest suite, compileall, wheel build and CLI/settings-diff help smoke tests.
- Added `scripts/qualify.ps1` for Windows PowerShell and `scripts/qualify.sh` for Linux/Debian. Both use an isolated `.venv`, install development/build dependencies and run the same core checks.
- Added `docs/TESTING_AND_QUALIFICATION.md` with Windows 10/11, Linux, Android Debian, backup/witness, settings non-mutation and manual device qualification checklists. Linked it from README.
- Hosted Windows CI is a current Windows runner, not exact Windows 10 hardware certification. Android Debian and physical independent witness custody still require the operator's devices.
- New platform matrix workflows have been added; exact results are pending. No final release readiness claim is made until they pass and manual blockers are resolved.


## Cross-platform test findings and fixes — 2026-11-19

- Initial Platform Qualification run exposed Windows-only failures: SQLite database connections were not explicitly closed before temporary backup/restore files were deleted (Windows `WinError 32`), and a signing-key test incorrectly treated POSIX permission bits as meaningful on Windows.
- Fixed backup SQLite connection lifetime through a helper that preserves transaction commit/rollback semantics and always closes the connection in `finally`; applied to inspection, backup and restore paths.
- Updated the update-signing key test to assert POSIX mode 0600 only on POSIX. On Windows, it checks key usability and documents inherited NTFS ACL requirements; no claim of automated Windows ACL verification is made.
- The first failing matrix run is retained as evidence. A corrected cross-platform matrix run is pending; do not count Windows as qualified until both Python versions and all CLI smoke steps pass.


### Follow-up CI correction

The first run after the Windows portability change stopped at Ruff because the new `contextmanager` import was out of order; the Windows pytest jobs had not yet validated that change. Import ordering was corrected in commit `909d8c85269992b9a9085a98fe467847dea8fdb4`. A fresh exact-head CI and platform matrix is required before accepting the fix.


### Second Windows permission-test correction

The corrected SQLite handle fix removed the prior backup/restore temp-file errors. The next Windows matrix run passed 343 tests and exposed one remaining platform-assumption in `tests/test_approval_key_lifecycle.py`: it asserted POSIX mode 0600 unconditionally. Updated the assertion to check POSIX mode only on POSIX and to check generated key readability/usability on Windows, where ACLs inherit from the parent directory. This does not certify Windows ACLs; operator verification with `icacls` remains required. The new test-only correction is commit `b4aee138a69a07d9f7881ad05d63cc165307721b`; exact-head matrix rerun pending.


## Read-only settings dashboard UI — 2026-11-19

- Added a Settings and Safety Controls panel to the local web dashboard with a responsive dark console layout suitable for desktop and mobile browsers.
- Added `GET /api/settings`, which reads and validates the configured settings file or reports safe built-in defaults when absent. Invalid/unreadable/symlinked configuration is reported as invalid; it is never silently replaced.
- The endpoint and dashboard remain GET-only and read-only. No settings apply form, policy mutation, feature activation or execution control was added. The existing `nexora settings diff` remains a preview only.
- Added tests for valid settings, invalid settings fail-closed behavior, dashboard panel rendering and absence of data-store creation.
- Settings path can be injected when creating the server for embedding/tests; default remains `config/settings.yaml`.


## Specification readiness audit — 2026-11-19

- Added `nexora spec-status`, a read-only aggregate for exact-source coverage,
  catalogue integrity, interaction-matrix coverage, precedence integrity and
  settings authorization readiness.
- Added `nexora settings policy-status` to report all settings without an
  approved per-setting authorization policy and the missing rollback controls.
- A policy file being present is not treated as approval; no policy schema or
  permission is inferred from arbitrary file contents.
- Missing capability IDs 1–84 and meta-rule IDs 1–15 remain explicitly missing.
- Unknown matrix pairs remain blocking; no family-level relationships or
  compatibility grants are fabricated.
- No settings mutation, policy mutation, autonomy increase, or execution path
  was added. See [SPECIFICATION_READINESS.md](SPECIFICATION_READINESS.md).


## Specification readiness audit — 2026-11-19

- Added `nexora spec-status`, a read-only aggregate for canonical source coverage,
  catalogue integrity, 40-family representation, 264×264 interaction coverage,
  precedence integrity and settings authorization readiness.
- Added `nexora settings policy-status` to report every current setting without
  an approved per-setting authorization rule and the required rollback controls.
- Added read-only web endpoints `GET /api/spec-status` and
  `GET /api/settings-policy`; both are rendered on the local dashboard.
- A settings policy file's presence or self-asserted approval fields are never
  treated as authorization. No policy schema, authority or rollback permission
  is inferred from unreviewed contents.
- Missing capability IDs 1–84 and meta-rule IDs 1–15 remain explicitly missing.
  Unknown interaction pairs remain blocking; no family-level relationships,
  symmetry, transitivity or compatibility grants are fabricated.
- No settings apply, policy mutation, capability activation, autonomy increase
  or execution path was added. The current defaults remain unchanged.
- Validation and CI are pending for the exact development-branch head.


## Read-only diagnostics additions — 2026-11-19

- Added explicit dependency graph reporting from declared `depends_on` edges,
  including strongly connected cycles and the number of unknown matrix pairs.
- Added `nexora governance-dependencies` and `GET /api/dependency-graph`.
- Added read-only `nexora audit-search` and `GET /api/audit-search`; both verify
  the entire audit hash chain and sequence before filtering by event, text or
  sequence window.
- Neither feature infers relationships, repairs audit history, enables
  capabilities or executes tools.
- Exact-head CI results must be checked for the current PR head before this
  increment is considered qualified.


## Verified audit search — 2026-11-19

- Added `nexora audit-search` with event, text, sequence-range and bounded
  result-count filters.
- Added loopback-only `GET /api/audit-search` and a dashboard search panel.
- Search verifies the complete SHA-256 audit chain and sequence continuity
  before returning results; invalid logs fail closed with no partial results.
- Missing logs are reported as `NOT_CONFIGURED`; no directory or log is created.
- Symlink and non-regular log paths are refused. Search is read-only and does
  not repair, rotate, truncate or rewrite audit history.
- Exact-head CI and platform qualification are pending for this increment.


## Proposal inspection — 2026-11-19

- Added `nexora proposals list` and `nexora proposals show` for stored
  self-family proposals and append-only human review history.
- The reader uses SQLite read-only mode and refuses missing, symlinked,
  non-regular or invalid stores without initializing storage.
- Operator-recorded `REVIEWED` labels are explicitly not treated as signed
  approvals, lifecycle promotion, policy authorization or execution grants.
- The stored payload digest is labeled recorded-but-not-recomputed because
  the current proposal table does not retain the original complete payload.
- Proposal review mutation and signed proposal approvals remain separate
  follow-up work; execution remains disabled.


## Source-backed family explorer — 2026-11-19

- Added `nexora family-map` and `GET /api/family-map` with a dashboard card.
- The report lists all 40 canonical family codes and shows names/counts only
  from source-backed catalogue records.
- Cross-cutting records are separate; conflicting source names are flagged.
- Missing capability IDs remain unassigned and unknown family values are
  counted rather than mapped by inference.
- No capability status, relationship, authorization or execution state changes.


## Structured proposal records API — 2026-11-19

- Added `GET /api/proposal-records` with bounded list and exact-ID lookup.
- The endpoint uses SQLite read-only mode and rejects duplicate/unknown query
  parameters, malformed IDs and invalid limits.
- Proposal review history remains display-only metadata; no signed approval,
  capability lifecycle transition, or execution grant is created.


## Witness key independence diagnostic — 2026-11-19

- Added `nexora witness-independence` to inspect backup, update and witness
  Ed25519 private keys without changing or exposing key material.
- Compares public fingerprints, file identity, resolved paths, parent
  directories and POSIX permissions where available.
- Explicitly does not claim different-host custody, remote witness operation,
  hardware-backed storage or independent human identity.
- Added tests for reused fingerprints, shared directories, symlinks and weak
  POSIX permissions.


## Signed trust-anchor rotation — 2026-11-19

- Added `nexora trust-rotate` to create an old-key-signed transition statement
  for backup, update or witness Ed25519 keys.
- Added `nexora trust-verify` to verify the statement against the existing
  pinned old public key and verify the embedded replacement key fingerprint.
- The workflow does not enroll the new key, change configuration, replace
  trust pins or activate a new key. Out-of-band operator confirmation remains
  mandatory.
- Added tests for valid transitions, wrong old pins, tampering, no-op rotation,
  output overwrite refusal, symlink refusal and CLI behavior.



## Expanded terminal diagnostics — 2026-11-19

- Extended the dependency-free TUI with read-only specification/matrix
  readiness, doctor diagnostics, source-backed family inventory, explicit
  dependency graph and settings authorization readiness views.
- Corrected the menu layout and added explicit view/exit numbering.
- Added regression coverage for all five views and for the invariant that
  the dashboard does not initialize the registry database.
- No settings, policy, lifecycle, capability, memory or execution mutation
  interface was added.
- Exact-head CI and cross-platform qualification are required before this
  increment is considered verified.
