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
- Dependency-free read-only terminal dashboard for system status, audit history, self-family proposals and capability registry; it exposes no mutation or execution controls.
- Loopback-only, GET-only local web dashboard with JSON diagnostic endpoints, Host-header validation and no control or execution endpoints.

## Repository map

The package is organized by responsibility under src/nexora/. Existing tested implementations remain authoritative; modular subpackages delegate to them rather than duplicating policy logic. See docs/PROJECT_LAYOUT.md.

## Self-* capability domains

See docs/SELF_FAMILIES.md. These six operational domains are provisional interfaces, **not canonical A–AN source families**. They cannot mutate policy, trusted memory or project files; cannot execute tools; and cannot enable themselves. Proposal generation remains separate from human approval and runtime authorization.

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

## Built-in GitHub updater

The updater checks the official `abdulraheemnohri/NEXORA-SENTINEL` repository's `main` branch. It does not update automatically in the background.

~~~bash
nexora update check
nexora update install --confirm
~~~

Installation is an explicit operator action and requires the official Git origin, the `main` branch, a clean working tree and a fast-forward-only update. It fetches the checked GitHub commit, updates the checkout and reinstalls the local package. If package installation fails, it attempts to roll the source checkout back to its previous commit. Keep a separate backup before updating. The updater requires Git, network access and pip; it is intended for a Git checkout, not a standalone wheel/zip installation. It does not bypass GitHub branch protections or verify a release signature. Review changes and CI before installing; a GitHub commit is not automatically a trusted release.

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
nexora memory-delete 1 --reason "No longer relevant" --confirm
~~~

Deletion hides a record from retrieval by appending a tombstone; the append-only audit record is retained. This is not secure physical erasure. The web dashboard only displays recent memory records and exposes no memory mutation endpoints.

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

The witness key must be different from the backup signing key. Distribute the witness public key separately and verify receipts against that external trust pin. This implementation signs and chains receipts, but it remains a local witness unless the witness process and key are hosted independently. It does not provide hardware-backed or remote attestation. Multi-process append locking is not implemented.

## Safety posture

- Autonomy defaults to L0; scheduler, sandbox and network flags default off.
- Proposal is not mutation; a due job is not permission to execute.
- Tool proposals are review-only; staged code is never executed.
- The staging workspace is not an OS-level sandbox.
- Ed25519 receipts prove possession of a pinned key, not real-world identity.
- Capability eligibility checks do not autonomously enable capabilities.
- Rollback records document a decision; they do not execute rollback.

## Not yet delivered

Full interactive API/control plane, local model inference runtime, production memory retrieval, OS-isolated sandbox, permission-controlled tool execution, autonomous self-evolution, complete source catalogue and reviewed interaction matrix. Android Debian/Pixel 6 device verification has not been performed by this remote repository work.

Read CONTRIBUTING.md, SECURITY.md, docs/ARCHITECTURE.md, docs/THREAT_MODEL.md, docs/PROJECT_STATUS.md and docs/SELF_FAMILIES.md.

License: Unlicense.
