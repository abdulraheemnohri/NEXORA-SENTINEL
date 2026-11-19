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
- Consistent SQLite online backups with Ed25519-signed manifests, external trust-key verification and non-overwriting restore.
- Separate Ed25519 witness receipt chains with independent public-key verification.
- Backup-first transactional SQLite migration and recovery-copy workflow.
- Six provisional self-* domains: observation, diagnostics, repair planning, learning, governance assistance and evolution proposals. Only read-only observation/diagnostics are enabled by default; all self-family outputs are proposals, never execution.
- Conservative YAML configuration profiles and validated settings loader.
- Durable local memory with source SHA-256 provenance, deterministic lexical retrieval, append-only records and auditable tombstones; no automatic model writes.
- Dependency-free read-only terminal dashboard for system status, audit history, self-family proposals, capability registry and evidence freshness; it exposes no mutation or execution controls.
- Loopback-only, GET-only local web dashboard with JSON diagnostic endpoints, Host-header validation and no control or execution endpoints.

## Repository map

The package is organized by responsibility under src/nexora/. Existing tested implementations remain authoritative; modular subpackages delegate to them rather than duplicating policy logic. See docs/PROJECT_LAYOUT.md.

## Self-* capability domains

See docs/SELF_FAMILIES.md. These six operational domains are provisional interfaces, **not canonical A–AN source families**. They cannot mutate policy, trusted memory or project files; cannot execute tools; and cannot enable themselves. Proposal generation remains separate from human approval and runtime authorization.

## Specification completeness

The supplied source records cover capabilities 85–264 (180 entries) and meta-rules 16–45 (30 entries). Original definitions 1–84 and 1–15 have not been supplied. The 264×264 interaction matrix remains empty by design. Missing source material is not fabricated. The catalog-check command therefore continues to report incomplete.

Run `nexora spec-status` for the aggregate specification, matrix and settings-governance readiness report, or `nexora settings policy-status` to inspect missing per-setting authorization and rollback controls. These reports are read-only; a populated policy file is not accepted as approval.

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

## Built-in GitHub updater

The updater checks the official `abdulraheemnohri/NEXORA-SENTINEL` repository's `main` branch, previews changed paths and summarizes GitHub Actions runs for the exact target commit. It does not update automatically in the background.

~~~bash
nexora update check
nexora update install --confirm
~~~

Installation is an explicit operator action and requires the official Git origin, the `main` branch, a clean working tree and a fast-forward-only update. It fetches the checked GitHub commit, updates the checkout and reinstalls the local package. If package installation fails, it attempts to roll the source checkout back to its previous commit. Keep a separate backup before updating. The updater requires Git, network access and pip; it is intended for a Git checkout, not a standalone wheel/zip installation. It does not bypass GitHub branch protections. Installation also requires the separately described signed-manifest trust gate. The check output includes a bounded file-change preview and CI state (`success`, `failure`, `pending`, or `unknown`). Installation is blocked when the latest commit has a known failed Actions run. A missing/unavailable CI report is shown as unverified, not as success. Review the preview and CI links before installing; a GitHub commit is not automatically a trusted release.

### Signed update manifest tooling

NEXORA includes Ed25519 manifest signing and verification primitives. A release manifest binds the official repository, the `main` ref, an exact 40-character commit SHA, version, timestamp and signer fingerprint. Verification requires a trusted public-key file supplied independently by the operator; a key shipped beside a manifest is not a trust anchor.

~~~bash
# Generate a dedicated update-signing key pair outside the repository.
# The private file is created with mode 0600 on POSIX; neither output is overwritten.
nexora update keygen \
  --private-key /secure/path/update-signing-key.pem \
  --public-key /secure/path/update-signing-key.pub.pem

# Protect the private key and distribute the public key through a separate trusted channel.
nexora update sign-manifest \
  --commit-sha YOUR_40_CHARACTER_COMMIT_SHA \
  --version 0.3.0 \
  --signing-key /secure/path/update-signing-key.pem \
  --output release.manifest.json

nexora update verify-manifest release.manifest.json \
  --trusted-key /secure/path/pinned-update-public-key.pem
~~~

The signer private key must have restrictive file permissions (0600 on POSIX). Manifest creation refuses to overwrite an existing file. Verification rejects schema changes, repository/ref mismatches, fingerprint mismatches and invalid signatures. The GitHub updater now requires a verified manifest and an independently pinned public key before installation. No project publisher key is embedded or distributed by the repository; operators must enroll the public key through a separate trusted channel. Do not treat an unsigned commit as a signed release. **Signing is an explicit operator attestation:** before signing, the operator must personally review the exact commit, its changes, dependencies and CI/build provenance and decide that they trust it. A green CI result is necessary for the updater gate but is not a substitute for security review; compromised CI or malicious code that passes tests remains a residual risk.

## Built-in LiteRT-LM local runtime

NEXORA includes a managed adapter for Google's official `litert-lm` CLI. It supports local `.litertlm` files and an explicitly approved Hugging Face repository import path. Hugging Face downloads are disabled by default and require both `network_downloads_enabled: true` in settings and the per-command `--confirm-download` flag; inference separately requires `runtime_enabled: true` and `--confirm-inference`. Python presets and model-provided tool execution remain disabled. CPU is the default backend; GPU must be selected explicitly.

Install the official CLI into the active NEXORA Python environment:

```bash
nexora litertlm install --confirm
nexora litertlm doctor
nexora litertlm models
```

The same installation can be selected through the optional package extra: `python -m pip install -e '.[litertlm]'`.

Place local model files under `models/` (the directory is ignored by Git). Review `config/litertlm.yaml` and set `runtime_enabled: true` only when you intentionally want to permit inference. Keep `network_downloads_enabled: false` unless you deliberately approve a model download. Python presets must remain disabled.

```bash
# One-shot local inference (explicit per-run approval)
nexora litertlm run --model model-name.litertlm \
  --prompt "Explain the NEXORA safety lifecycle" --confirm-inference

# Interactive local chat
nexora litertlm chat --model model-name.litertlm --confirm-inference

# Import from Hugging Face and run the requested Qwen3 reasoning model.
# This downloads several GB; enable network_downloads_enabled in config first.
nexora litertlm run \
  --from-huggingface-repo=litert-community/Qwen3-4B-Thinking-2507 \
  --prompt "Explain the NEXORA safety lifecycle" \
  --confirm-download --confirm-inference

# Explicit CPU/GPU choice for a local model
nexora litertlm run --model model-name.litertlm \
  --backend cpu --prompt "Hello" --confirm-inference
```

Use `nexora web` and open `http://127.0.0.1:8765` to view the read-only Runtime & Models page, or query `/api/runtime`. The page never launches a model or changes runtime settings. The adapter uses an argument vector (never a shell), validates Hugging Face repository IDs, enforces a bounded timeout, and reports CLI errors without enabling tool execution. The model output is untrusted text and cannot approve actions or invoke NEXORA tools. The Qwen3-4B-Thinking-2507 repository publishes an approximately 2.5 GB primary bundle and describes a 4096-token context; ensure adequate storage and free memory before downloading or running it. A Pixel-class device may terminate the process under memory pressure; successful desktop/CI tests do not establish phone compatibility.

**Platform note:** Google's CLI documentation lists Linux, macOS, Windows, Android and Raspberry Pi, but actual Python wheel availability and accelerator support depend on the host architecture and environment. Android Debian/Pixel compatibility must be verified on-device; successful package installation is not assumed.

## Settings inspection and validation

Inspect the validated settings file (defaults are used only when the file is absent):

~~~bash
nexora settings show
nexora settings validate --config config/settings.yaml
~~~

The settings commands are read-only. Unknown keys, invalid values, malformed files and non-file paths fail closed; an existing invalid file is never silently replaced with defaults. Current settings constrain autonomy to L0/L1 and keep scheduler, sandbox and network flags disabled by default. These commands do not enable execution, change policy or write configuration.

## Explicit local memory commands

Memory is only written by an explicit operator command; inference cannot silently store trusted memories.

~~~bash
nexora memory-add "A note to remember" --source operator-note
nexora memory-search "note remember"
nexora memory-tombstone 1 --reason "No longer relevant" --confirm
~~~

`memory-tombstone` (also available as the backward-compatible `memory-delete` and `memory-hide` aliases) hides a record from retrieval by appending a tombstone; the append-only record and audit history remain on disk. CLI output explicitly reports `physical_erasure: false`. This is not secure physical erasure from SQLite files, backups or filesystem storage. The web dashboard only displays recent memory records and exposes no memory mutation endpoints.

## Local read-only web dashboard

Start the dashboard on loopback only (default port 8765):

~~~bash
nexora web
~~~

Open http://127.0.0.1:8765 on the same device. Choose another local port with `nexora web --port 9000`. The server refuses non-local Host headers, binds only to `127.0.0.1`, serves GET-only diagnostics and rejects mutation methods. It does not create the data directory, initialize databases or expose tools. It is not a remote administration interface.

## Signed backup and restore

Initialize the registry and create a dedicated backup signing key pair:

~~~bash
nexora registry-init
nexora backup-keygen
~~~

Keep data/backup-signing-key.pem private and protected. Distribute data/backup-signing-key.pub.pem to restore/verification machines through a separate trusted channel. Do not trust a public key merely because it arrived beside a backup.

Create and verify a backup:

~~~bash
nexora backup
nexora verify-backup data/backups/registry.sqlite3
nexora restore data/backups/registry.sqlite3 data/registry-restored.sqlite3
~~~

Use --signing-key PATH with backup, and --trusted-key PATH with verify-backup or restore, when using non-default key paths. Restore refuses to overwrite an existing destination. The backup uses SQLite's online backup API, including committed WAL data.

## Independent witness receipts

Create a second, distinct key pair for the witness process:

~~~bash
nexora backup-keygen \
  --private-key data/witness-signing-key.pem \
  --public-key data/witness-signing-key.pub.pem
nexora witness-backup data/backups/registry.sqlite3
nexora verify-witness data/witness/receipts.jsonl
~~~

The witness key must be different from the backup signing key. Distribute the witness public key separately and verify receipts against that external trust pin. This implementation signs and chains receipts, but it remains a local witness unless the witness process and key are hosted independently. It does not provide hardware-backed or remote attestation. Witness appends and verification use cross-process file locking on POSIX and Windows.

## Safety posture

- Autonomy defaults to L0; scheduler, sandbox and network flags default off.
- Proposal is not mutation; a due job is not permission to execute.
- Tool proposals are review-only; staged code is never executed.
- The staging workspace is not an OS-level sandbox.
- Ed25519 receipts prove possession of a pinned key, not real-world identity.
- Capability eligibility checks do not autonomously enable capabilities.
- Rollback records document a decision; they do not execute rollback.

## Not yet delivered

Full interactive API/control plane, semantic/embedding memory retrieval, OS-isolated sandbox, permission-controlled tool execution, autonomous self-evolution, complete source catalogue and reviewed interaction matrix. The optional LiteRT-LM CLI adapter exists, but an autonomous inference/tool loop is not enabled. Android Debian/Pixel 6 device verification has not been performed by this remote repository work.

Read CONTRIBUTING.md, SECURITY.md, docs/ARCHITECTURE.md, docs/THREAT_MODEL.md, docs/PROJECT_STATUS.md and docs/SELF_FAMILIES.md.

License: Unlicense.


## Signed software updates

Update installation is fail-closed and now requires an Ed25519-signed manifest plus a public key pinned through an independent trusted channel. Generate a dedicated signing keypair once, protect the private key offline, and independently provision the public key on each client:

```bash
nexora update keygen \
  --private-key ~/.config/nexora/update-private.pem \
  --public-key ~/.config/nexora/update-public.pem

# On the release/signing system, after reviewing and testing the exact commit:
nexora update sign-manifest \
  --commit-sha <40-character-main-commit-sha> \
  --version <release-version> \
  --signing-key /secure/path/update-private.pem \
  --output release.manifest.json

# On the client, verify the manifest and install only that exact main commit:
nexora update verify-manifest release.manifest.json \
  --trusted-key ~/.config/nexora/trusted-update-public.pem
nexora update install --confirm \
  --manifest release.manifest.json \
  --trusted-key ~/.config/nexora/trusted-update-public.pem
```

The updater requires the manifest commit to equal the current GitHub `main` SHA, a clean worktree, fast-forward ancestry, and successful CI for that exact commit. Missing, pending, failed, mismatched, or untrusted evidence blocks installation. The repository does not ship a publisher key: operators must verify and pin the public key independently. A locally generated key is not automatically a trusted publisher key.




## Cryptographic lifecycle history and independent checkpoints

New lifecycle, revocation and rollback events are recorded in an ordered SHA-256 hash chain in the same SQLite transaction as their source event. Verification checks sequence continuity, canonical payloads, source-row equality and complete post-activation coverage. Existing records are excluded using activation watermarks bound into the chain genesis; they remain explicitly unverified.

```bash
nexora lifecycle-history
nexora lifecycle-chain-attest \
  --witness-key /secure/lifecycle-witness-private.pem \
  --witness-log /separate-witness-storage/lifecycle.jsonl \
  --confirm
nexora lifecycle-chain-verify \
  --witness-log /separate-witness-storage/lifecycle.jsonl \
  --trusted-witness-key /trusted/lifecycle-witness-public.pem
```

The checkpoint private key, witness log and trusted public key must be retained independently from the registry database. A checkpoint becomes stale whenever new events are appended; verification then fails until a new checkpoint is deliberately created. The local database chain alone is not an independent trust anchor. See `docs/LIFECYCLE_CHAIN.md`.

## Lifecycle history and regression diagnostics

The read-only lifecycle report replays the existing SQLite lifecycle, revocation and rollback event tables. It detects structural inconsistencies such as non-sequential transitions, replay/current-state divergence and revocation/control-state mismatches. It does not change state or execute capabilities.

```bash
nexora lifecycle-history
nexora lifecycle-history --capability-id 85
nexora regression-report
```

The dashboard exposes `/api/lifecycle-history`. Legacy lifecycle rows have append-only SQLite triggers but no cryptographic event hash chain; the report therefore marks history authenticity `UNVERIFIED`. Structural consistency is not proof against a privileged database rewrite. Canonical expiry semantics have not been supplied, so freshness remains UNKNOWN unless an operator explicitly records a timezone-aware expiry. See `docs/EVIDENCE_FRESHNESS.md`.

Capability evidence ledger: see `docs/CAPABILITY_EVIDENCE.md` for append-only evidence references, hash-chain verification, CLI usage, and security limits.



## Capability family evidence evaluation

The family evaluator aggregates source-backed capability records and their verified evidence-ledger coverage. It keeps catalogue status separate from evidence status, distinguishes missing evidence tokens from evidence that is present but still awaiting human authorization, and exposes source gaps without inventing missing family definitions or dependencies.

```bash
nexora family-evaluation
nexora family-evaluation --family O
nexora family-evaluation --database data/registry.sqlite3
```

The read-only dashboard exposes `/api/family-evaluation` and accepts an optional `?family=O` filter. This is a diagnostic report only: no lifecycle promotion, policy mutation, or capability execution occurs. See `docs/CAPABILITY_FAMILY_EVALUATION.md`.


## Recovery simulation evidence and history

Recovery simulations can be persisted as metadata-only events, signed by a separate Ed25519 witness key, and linked into the hash-chained audit log. Configure the paths and thresholds in `config/recovery.json`. Automatic restore and deletion remain prohibited.

Create an independent witness keypair (never reuse the backup-signing key):

```bash
nexora backup-keygen \
  --private-key data/recovery-witness-signing-key.pem \
  --public-key data/recovery-witness-signing-key.pub.pem
```

After independently protecting and pinning the public key, record a confirmed simulation:

```bash
nexora recovery-simulate data/backups/registry.sqlite3 \
  --trusted-key /secure/off-device/backup-signing-key.pub.pem \
  --confirm-simulation
nexora recovery-history
nexora recovery-readiness --config config/recovery.json
```

The readiness report now includes the latest independently witnessed simulation state. The read-only dashboard exposes `/api/recovery-history` and incorporates verified simulation evidence into `/api/recovery-readiness`. Unwitnessed or tampered history is excluded or reported invalid. Simulation never replaces a live database, removes backups, or authorizes production restore.


Compare two verified recovery points without restoring either:

```bash
nexora recovery-compare data/backups/previous.sqlite3 data/backups/current.sqlite3 \
  --trusted-key /secure/off-device/backup-signing-key.pub.pem
```

The comparison reports schema and SQLite migration-version differences only; it does not inspect or compare application row data.


## OS sandbox readiness (preflight only)

Run `nexora sandbox-check` to inspect whether a Linux host and Bubblewrap
binary are present. The check does not execute Bubblewrap, create namespaces,
or run staged content. Its result is `UNAVAILABLE` or `UNVERIFIED`; it never
returns a readiness grant and never enables execution. The loopback dashboard
also exposes the report at `/api/sandbox-readiness`. See
`docs/SANDBOX_READINESS.md` for the remaining isolation and adversarial-test
gates. Android Debian/Termux is not currently qualified.


## Evidence freshness intelligence

Evidence records may include an explicit operator-declared expiry. For example:

```bash
nexora evidence add 85 --type test_report \
  --reference artifact://reports/test-85.json \
  --sha256 <64-character-lowercase-sha256> \
  --operator operator-1 --expires-at 2027-01-01T00:00:00Z --confirm

nexora evidence freshness
nexora evidence freshness --capability-id 85
```

The evidence freshness report is available in the web dashboard at `/api/evidence-freshness` and in terminal dashboard option 5. Records without explicit expiry remain UNKNOWN. The feature is read-only and does not infer missing requirements, revoke evidence, or alter lifecycle state. See `docs/EVIDENCE_FRESHNESS.md`.


### Evidence provenance

Evidence records can optionally carry operator-declared source origin and revision metadata:

```bash
nexora evidence add 85 --type implementation_reference \
  --reference git:commit/0123456789abcdef \
  --sha256 YOUR_64_CHARACTER_SHA256 --operator operator-1 \
  --source-uri https://github.com/example/project \
  --source-revision 0123456789abcdef \
  --collected-at 2026-11-19T10:00:00+05:00 --confirm

nexora evidence provenance
```

The read-only report is also available at `/api/evidence-provenance` and terminal dashboard option 6. These are provenance declarations, not independent source authentication or remote change detection. See `docs/EVIDENCE_FRESHNESS.md`.


## Settings change preview (read-only)

Compare a proposed settings file with the current configuration without applying it:

```bash
nexora settings diff --config config/settings.yaml --candidate proposed-settings.yaml
```

A changed configuration returns `REVIEW_REQUIRED` (exit code 3), lists changed fields, and marks authorization as `NOT_EVALUATED`. This is intentional: no approved per-setting authorization matrix exists yet. The command cannot write settings, enable features, or grant autonomy. A matching configuration returns `NO_CHANGES`. Invalid or missing candidate files fail closed.

## Testing and platform qualification

See [`docs/TESTING_AND_QUALIFICATION.md`](docs/TESTING_AND_QUALIFICATION.md) for the reproducible Windows PowerShell and Linux qualification runners, four-job OS/Python CI matrix, first-run smoke checks and manual device/trust checklist. On Windows, run `Set-ExecutionPolicy -Scope Process Bypass` then `.\scripts\qualify.ps1`. On Linux/Debian, run `bash scripts/qualify.sh`. A green hosted CI run does not certify a physical Windows 10, Android or independent witness device.


## Specification and governance readiness

Run `nexora spec-status` for a read-only aggregate of canonical source coverage,
the 264 × 264 interaction matrix, precedence integrity and settings authorization
readiness. Run `nexora settings policy-status` to inspect the missing per-setting
authorization and rollback requirements. These commands do not populate missing
specifications, infer relationships, approve settings, or enable execution.
See [Specification Readiness](docs/SPECIFICATION_READINESS.md).


## Specification readiness and authorization gaps

Run the read-only readiness reports:

```bash
nexora spec-status
nexora settings policy-status
```

The reports identify missing source-backed capability definitions and meta-rules, unknown pairs in the 264 × 264 interaction matrix, and settings whose authorization/rollback rules have not been approved. They never reconstruct missing definitions or infer relationships. A policy file is not approval. Settings application and autonomous execution remain disabled.


## Audit search

Search the verified local audit history without changing it:

```bash
nexora audit-search --event policy.decision --limit 100
nexora audit-search --contains permission --from-sequence 10
```

The read-only web endpoint is `GET /api/audit-search`. Search verifies the full
hash chain and sequence before returning filtered results. Corrupt or unsafe
audit paths fail closed; search never repairs or rotates the log.


## Verified audit search

Search the audit chain without modifying it:

```bash
nexora audit-search
nexora audit-search --event policy.denied
nexora audit-search --contains "capability_id" --from-sequence 10 --to-sequence 100 --limit 50
```

The command verifies the entire hash chain before returning results. Corruption, missing sequence numbers, symlinks and non-regular files fail closed. The loopback dashboard exposes the same filters at `GET /api/audit-search`. Searches are read-only; no records are rewritten or deleted.


## Proposal inspection

Inspect stored self-family proposals without initializing a database or granting execution:

```bash
nexora proposals list
nexora proposals list --limit 50
nexora proposals show PROPOSAL_ID
```

The commands use SQLite read-only mode. Operator-recorded review labels remain separate from signed approvals; every proposal remains execution-disabled.


## Capability family explorer

Run `nexora family-map` or open `GET /api/family-map` in the local dashboard to inspect the 40 canonical family slots and their source-backed capability counts. Missing capabilities remain unassigned, cross-cutting entries are shown separately, and conflicting family names are flagged. No family relationships or missing assignments are inferred.


The local dashboard also exposes structured proposal history at `GET /api/proposal-records` (optionally filtered by `proposal_id` or `limit`). This endpoint is read-only and does not turn a human review label into signed approval.


## Witness key separation check

Run `nexora witness-independence --backup-private-key PATH --update-private-key PATH --witness-private-key PATH` to compare the backup, update and witness signing keys. The check is read-only. It can identify duplicate fingerprints, shared files/directories and weak POSIX private-key permissions, but it cannot establish off-device custody or hardware-backed protection.
