# Changelog

## Unreleased

- Added Evidence Freshness Intelligence with optional, timezone-aware operator-declared expiry metadata in evidence ledger schema v3.
- Added read-only freshness reports to CLI, loopback web dashboard and terminal dashboard, with UNKNOWN/EXPIRED/CURRENT/UNVERIFIED/INVALID_METADATA classifications.
- Preserved legacy evidence hashes and UNKNOWN semantics; no inferred expiry, evidence deletion, lifecycle mutation or execution.


## 0.2.0 — 2026-11-18

- Added a SHA-256 hash chain for new lifecycle, revocation and rollback events, with legacy watermarks explicitly excluded and bound into the chain genesis.
- Added read-only chain verification and operator-driven Ed25519 external witness checkpoint/verification commands.

- Added read-only artifact integrity verification against exact evidence-ledger records.
- Added lifecycle history replay and structural regression diagnostics for lifecycle, revocation and rollback records.
- Added lifecycle history CLI commands and a loopback GET-only dashboard endpoint; legacy lifecycle authenticity remains explicitly unverified.

- Added modular responsibility-oriented package structure.
- Added conservative YAML configuration profiles and validated YAML loading.
- Added SQLite online backup, integrity verification and non-overwriting restore.
- Added proposal-only planning, explicit disabled execution boundary, local memory records, provenance and evolution review gates.
- Added governance interaction lookup that blocks unknown relations.
- Updated project status and documentation to distinguish implemented features from planned interfaces.

## 0.1.0

- Established the fail-closed safety kernel, capability lifecycle, audit chain, kill switch and local platform foundations.
