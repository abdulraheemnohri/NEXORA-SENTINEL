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

Full TUI/web/API experiences, local model inference runtime, production memory retrieval, OS-isolated sandbox, permission-controlled tool execution, autonomous self-evolution, complete source catalogue and reviewed interaction matrix. Android Debian/Pixel 6 device verification has not been performed by this remote repository work.

Read CONTRIBUTING.md, SECURITY.md, docs/ARCHITECTURE.md, docs/THREAT_MODEL.md, docs/PROJECT_STATUS.md and docs/SELF_FAMILIES.md.

License: Unlicense.
