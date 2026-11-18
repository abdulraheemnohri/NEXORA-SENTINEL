# Project Status — NEXORA Sentinel

Last updated: 2026-11-18

## Current milestone

Safety kernel, durable self-family proposal review, and a dependency-free read-only terminal dashboard. This is still a governance/runtime foundation, not a completed autonomous agent.

## Implemented

- Fail-closed policy kernel, persistent emergency stop and hash-chained audit log.
- Evidence-gated lifecycle registry, signed Ed25519 approvals, append-only lifecycle/revocation/rollback records.
- Persistent budget ledger, review-only scheduler and tool proposal queue.
- WAL-safe signed SQLite backups, external trust-key verification, non-overwriting restore, independent witness receipts.
- Backup-first transactional migrations and recovery-copy workflow.
- Six provisional self-* domains; typed L0/L1 settings, deterministic proposals and durable append-only review records.
- Read-only terminal dashboard: overview, audit chain, proposals and capability registry. SQLite dashboard views open the database in read-only mode and do not initialize or mutate it.
- Loopback-only GET web dashboard and JSON diagnostic endpoints; Host header is checked, mutation methods are rejected, and the server binds only to 127.0.0.1.
- Conservative YAML profiles, modular package structure and TLA+ lifecycle model.
- Built-in GitHub updater: checks the official main-branch commit, previews changed paths, summarizes Actions runs for the exact target SHA, and blocks installation on a known failed CI run. Explicit installation still requires confirmation, official origin, main branch, clean worktree and fast-forward-only history. It reinstalls the local package and attempts source rollback if installation fails.
- Read-only settings inspection and validation CLI: missing files use safe L0 defaults; existing invalid files and unknown keys fail closed; no settings mutation or execution toggles are exposed.
- Durable explicit-write memory store with SHA-256 source fingerprints, deterministic AND-term retrieval, append-only record/event tables, tombstone deletion and legacy-store import; read-only search does not create missing storage.

## Explicitly incomplete

- Canonical capability source records 1–84 and meta-rules 1–15 have not been supplied.
- The 264×264 interaction matrix remains unknown/unpopulated.
- Interactive API/control plane is not shipped; the local web dashboard is read-only diagnostics only.
- Model inference remains disabled. Trusted memory now supports explicit local writes and deterministic provenance-verified lexical retrieval; no semantic/embedding retrieval or model-originated writes.
- Staging is not an OS-enforced sandbox; no tool or code execution is enabled.
- Self-* domains do not autonomously repair, learn into trusted memory, or evolve.
- Operator labels do not prove identity; local witness is not remote attestation.
- Android Debian/Pixel verification has not been performed.

## Next priorities

1. Add externally pinned update signature/release provenance verification; the current updater preview and CI check are advisory except that a known failed CI run blocks installation.
2. Add a controlled, audited settings-change workflow only after defining per-setting authorization and rollback requirements.
3. Test read-only dashboard behavior on supported Linux and Android Debian terminals.
4. Validate the read-only web dashboard on Linux and Android Debian; retain loopback-only binding.
5. Obtain missing source-backed capability/meta-rule definitions and reviewed interaction relationships.
6. Design OS-enforced sandbox isolation before any execution feature.
7. Verify installation and behavior on Pixel/Android Debian locally.

No merge or release is performed without owner approval.
