# NEXORA-SENTINEL

**Self-Terminal Autonomous Intelligence Platform · STA-264**  
**Autonomy Through Verifiability · v0.2.0**

NEXORA Sentinel is a local-first safety, governance and agent-runtime foundation. It is an evolving project, **not yet a completed autonomous agent**. Its governing invariant is:

> Autonomy scales only as fast as verifiability does.

## Current working capabilities

- Fail-closed policy kernel, persistent emergency stop and hash-chained audit log.
- Sequential evidence-gated capability lifecycle and SQLite capability registry.
- Ed25519 approval receipts for APPROVED/ENABLED transitions, pinned-key trust and replay prevention.
- Persistent resource budget ledger and review-only scheduler.
- Tool proposal queue; proposed tools are not invoked.
- Staging workspace with path-containment checks; staged code is not executed.
- Consistent SQLite online backup, manifest/hash verification and non-destructive restore.
- Conservative YAML configuration profiles and validated settings loader.
- Modular package surfaces for core, oversight, governance, capabilities, runtime, intelligence, memory, evolution, terminal and storage.

## Repository map

The package is organized by responsibility under src/nexora/. Existing tested implementations remain authoritative; modular subpackages delegate to them rather than duplicating policy logic. See docs/PROJECT_LAYOUT.md.

## Specification completeness

The supplied source records cover capabilities 85–264 (180 entries) and meta-rules 16–45 (30 entries). Original definitions 1–84 and 1–15 have not been supplied. The 264×264 interaction matrix remains empty by design. Missing source material is not fabricated. The catalog-check command therefore continues to report incomplete.

## Install — Linux / Android Debian

~~~bash
bash scripts/install_linux.sh
.venv/bin/nexora status
~~~

For Android Debian, use bash scripts/install_android_debian.sh.

## Verify

~~~bash
bash scripts/verify.sh
~~~

## CLI

~~~bash
nexora status
nexora catalog-check
nexora check ACTION --risk low
nexora audit
nexora kill
nexora resume
nexora registry-init
nexora backup
nexora verify-backup data/backups/registry.sqlite3
nexora restore data/backups/registry.sqlite3 data/registry-restored.sqlite3
~~~

The backup command expects the registry database at data/registry.sqlite3; initialize it with nexora registry-init. Backups use SQLite's online backup API (including committed WAL data). A SHA-256 sidecar detects corruption but is **not an authenticated signature**. Restore refuses to overwrite an existing destination.

## Safety posture

- Autonomy defaults to L0; scheduler, sandbox and network flags default off.
- Proposal is not mutation; a due job is not permission to execute.
- Tool proposals are review-only; staged code is never executed.
- The staging workspace is not an OS-level sandbox.
- Ed25519 receipts prove possession of a pinned key, not real-world identity.
- Capability eligibility checks do not autonomously enable capabilities.
- Rollback records document a decision; they do not execute rollback.

## Not yet delivered

Full TUI/web/API experiences, local model inference runtime, production memory retrieval, OS-isolated sandbox, permission-controlled tool execution, autonomous self-evolution, complete source catalogue and reviewed interaction matrix. Android Debian/Pixel 6 device verification has not been performed by this remote repository work.

Read CONTRIBUTING.md, SECURITY.md, docs/ARCHITECTURE.md, docs/THREAT_MODEL.md, and docs/PROJECT_STATUS.md.

License: Unlicense.
