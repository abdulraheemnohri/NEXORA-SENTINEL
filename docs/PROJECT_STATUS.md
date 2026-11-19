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


## Kill-switch marker lookup hardening

- The emergency-stop marker is inspected with lstat(), not Path.exists(), so a dangling symlink cannot be mistaken for a clear switch.
- A genuinely missing marker is the only clear state; permission, I/O and invalid-path inspection errors are treated as engaged.
- Added regression coverage proving the policy kernel denies a low-risk action when the marker is a dangling symlink, and that lookup errors fail closed.
- This is a narrow local-filesystem hardening change; it does not claim protection from a privileged local attacker who can alter the data directory.
- Implementation/test head `fb557d6bdf22ed359ae5c38d7c0eb7d6090be8b8` passed exact-SHA GitHub Actions: CI run `44450276066`, Tests `44450276001`, Security `44450276004`, Build `44450276131`, and Formal Verification `44450276073` all completed successfully.
- Executed evidence: Ruff passed; pytest reported 338 passed; Python compileall passed; `pip check` passed; wheel build passed; TLC formal verification passed.
- These are GitHub-hosted Linux checks. No Android/Pixel device test is claimed, and no release was published.
- Prior conversation/source retrieval again found no original source text for capability IDs 1–84 or meta-rules 1–15. Those records remain a human-supplied source blocker; no definitions were fabricated.
- No action execution or autonomy level is enabled by this change.
