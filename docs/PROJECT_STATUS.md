# Project Status — NEXORA Sentinel

Last updated: 2026-11-18

## Current milestone

Safety kernel, modular package structure, local platform foundations and SQLite backup/restore. The project is not complete.

## Implemented and CI-covered

- Fail-closed policy kernel, persistent emergency stop and hash-chained audit log.
- Evidence-gated sequential lifecycle validator and safety-first precedence resolver.
- SQLite capability registry with append-only lifecycle, revocation and rollback-decision events.
- Ed25519 approval receipts; APPROVED and ENABLED require scoped signed receipts. Receipt nonce consumption and lifecycle mutation share one SQLite transaction.
- Persistent budget ledger, review-only scheduler and tool proposal queue.
- Safe staging workspace with path containment; submitted code is not executed.
- SQLite online backup, SHA-256 manifest verification and non-overwriting restore.
- Conservative YAML settings profiles and validated YAML loader.
- Modular packages for core, oversight, governance, capabilities, runtime, intelligence, memory, evolution, terminal, interfaces and storage.
- SQLite migration runner, local memory records, provenance helpers and proposal-only evolution gates.
- Formal TLA+ lifecycle model checked by TLC in GitHub Actions.
- CLI, install/verify scripts, documentation and GitHub CI workflows.

## Latest verification — commit 6cd15de9d3ecbecf64dd7b8fc93555798e8b9e3d

- Ruff: passed.
- Pytest: 54 passed.
- Python compileall: passed.
- Dependency consistency (pip check): passed.
- TLA+ TLC lifecycle invariant check: passed.
- Python wheel build: passed.
- GitHub Actions checks ran on GitHub-hosted Linux/Python 3.12.16. These results do not constitute Android Debian or Pixel 6 device testing.

## Explicitly incomplete

- Capability source records 1–84 and meta-rules 1–15 have not been supplied.
- Interaction matrix dimensions are 264×264 but entries remain unknown/empty.
- TUI, web dashboard and API are namespace surfaces only; no interactive UI/server is shipped.
- Model runtime and inference are disabled; local model inventory is read-only.
- Memory retrieval and knowledge graph integration remain limited foundations.
- Staging is not an OS-level sandbox; no tool execution is enabled.
- Operator labels are not cryptographic identity proof.
- Backup SHA-256 manifests are unsigned and do not provide authenticated provenance.
- Android Debian/Pixel device testing has not been performed remotely.

## Next priorities

1. Sign backup manifests and add independent witness verification.
2. Add migration compatibility and restore drills across schema versions.
3. Build a read-only TUI and local dashboard before any execution controls.
4. Complete source-backed capability and meta-rule definitions from the project owner.
5. Populate interaction-matrix relationships only from reviewed source specifications.
6. Design OS-enforced sandbox isolation before considering code execution.
7. Conduct Android Debian installation and device verification locally.

PR #1 remains open and unmerged. Do not merge or release without explicit owner approval.
