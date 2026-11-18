# Project Status — NEXORA Sentinel

Last updated: 2026-11-18

## Current milestone

Safety kernel, durable self-family proposal review, source-backed capability family evidence evaluation, and read-only terminal/web dashboards. This is still a governance/runtime foundation, not a completed autonomous agent.

## Implemented

- Fail-closed policy kernel, persistent emergency stop and hash-chained audit log.
- Evidence-gated lifecycle registry, signed Ed25519 approvals, append-only lifecycle/revocation/rollback records.
- Persistent budget ledger, review-only scheduler and tool proposal queue.
- WAL-safe signed SQLite backups, external trust-key verification, non-overwriting restore, independent witness receipts.
- Backup-first transactional migrations and recovery-copy workflow.
- Six provisional self-* domains; typed L0/L1 settings, deterministic proposals and durable append-only review records.
- Read-only terminal dashboard: overview, audit chain, proposals and capability registry. SQLite dashboard views open the database in read-only mode and do not initialize or mutate it.\n- Read-only capability family evaluator: aggregates source-backed family membership, catalogue status, and verified evidence-ledger coverage; distinguishes missing evidence from evidence awaiting human authorization; exposes a CLI and GET-only dashboard endpoint without lifecycle promotion.
- Loopback-only GET web dashboard and JSON diagnostic endpoints; Host header is checked, mutation methods are rejected, and the server binds only to 127.0.0.1.
- Conservative YAML profiles, modular package structure and TLA+ lifecycle model.
- Built-in GitHub updater: checks the official main-branch commit, previews changed paths, summarizes Actions runs for the exact target SHA, and blocks installation on a known failed CI run. Explicit installation still requires confirmation, official origin, main branch, clean worktree and fast-forward-only history. It reinstalls the local package and attempts source rollback if installation fails. Separate Ed25519 update-manifest signing and verification commands bind repository/ref/commit/version and require an externally supplied trusted public key; a dedicated update-key generator creates non-overwriting key files with restrictive private-key permissions.
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

1. Enroll an independently distributed update-signing public key and wire verified signed manifests into the updater's installation gate; current manifest verification is a separate operator command and is not yet mandatory for installation.
2. Add a controlled, audited settings-change workflow only after defining per-setting authorization and rollback requirements.
3. Test read-only dashboard behavior on supported Linux and Android Debian terminals.
4. Validate the read-only web dashboard on Linux and Android Debian; retain loopback-only binding.
5. Obtain missing source-backed capability/meta-rule definitions and reviewed interaction relationships.
6. Design OS-enforced sandbox isolation before any execution feature.
7. Verify the official LiteRT-LM CLI and a small `.litertlm` model on Pixel/Android Debian; only then test Qwen3-4B-Thinking-2507 with memory monitoring, recording CPU/GPU stability, load time and token throughput without making unmeasured performance claims.

No merge or release is performed without owner approval.


## Update trust gate

The updater install path now requires a signed Ed25519 manifest verified against a separately provisioned public key, exact commit-SHA equality with GitHub main, successful exact-SHA CI, a clean worktree and fast-forward ancestry. No publisher key is embedded or assumed. A release signing workflow and independently distributed publisher key remain operator/release-process tasks.
