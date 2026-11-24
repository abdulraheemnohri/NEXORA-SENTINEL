# Threat model

## Scope and security posture

NEXORA-SENTINEL v0.2.0 is a local-first governance and runtime foundation, not an autonomous tool-execution agent. Autonomy defaults to L0. Tool execution, generated-code execution, automatic capability promotion and policy mutation are not implemented. The staging workspace performs path-contained file staging only; it is not an OS security boundary. The new sandbox preflight is read-only and never launches Bubblewrap or payloads; it reports UNAVAILABLE or UNVERIFIED and never authorizes execution.

## Protected assets

- Operator approval, update, backup and witness private keys and their trust pins.
- Capability registry, lifecycle state, revocation history and approval nonce records.
- Backup snapshots, signed manifests and restore destinations.
- Audit and witness evidence.
- Emergency-stop state and fixed safety policy.
- Local memory records, provenance and tombstone history.
- Runtime configuration, model files and staged proposal artifacts.

## Implemented controls

- Unknown actions and unknown governance relationships fail closed; runtime policy mutation is disabled.
- Emergency stop blocks policy decisions.
- Audit append serializes chain verification, sequence allocation and durable writes across cooperating processes using a persistent sidecar lock. Audit state paths are opened as regular non-symlink files, and append verification plus write use one checked descriptor; read-only audit search uses the same path check. Kill-switch engage/resume plus their audit records use a separate transition lock.
- A failed audit append during resume leaves the kill marker in place. The locks coordinate callers using these APIs; they do not prevent direct file edits or privileged/non-cooperating writers.
- APPROVED and ENABLED lifecycle transitions require scoped Ed25519 receipts and one-time nonce consumption in the same SQLite transaction as the state change. ENABLED, revocation and rollback authorization use multiple distinct enrolled signing keys as documented in GOVERNANCE.md.
- SQLite backups use the online backup API, signed canonical manifests, externally supplied trusted public keys, integrity checks and non-overwriting restore.
- Backup verification opens the database and manifest as checked regular-file descriptors, rejects symlink/non-regular leaf paths, copies the database into a private temporary snapshot, and verifies the signed digest, byte count and SQLite metadata against that copy. Restore consumes the exact same verified snapshot rather than reopening the original pathname, closing the verify-then-reopen substitution window; the destination is checked with `lstat` and published without replacement.
- Witness receipts use a separate Ed25519 key, signed sequence numbers and a previous-receipt hash chain. The signed witness stream rejects symlink/non-regular leaf paths and verifies/appends through one checked descriptor while a POSIX `flock` or Windows `msvcrt` sidecar lock is held. The legacy local witness stream uses the same checked-file and cross-process append boundary; neither stream is a remote or hardware trust anchor.
- Recovery-history JSONL writes and reads use checked regular-file descriptors under a persistent history lock. The reader verifies the signed receipt chain and extracts recovery-event hashes in one locked descriptor pass, avoiding a verify-then-reopen race; only history rows whose digest appears in that verified receipt snapshot are returned. Symlink/non-regular history paths fail closed.
- Update manifests bind the repository, main ref, exact commit SHA, version, timestamp and signer fingerprint. Installation requires an independently pinned public key and successful CI for the exact commit.
- The web dashboard binds to loopback, is GET-only and exposes no mutation or execution endpoints.
- Memory records are explicitly written, provenance-fingerprinted and append-only. A delete request appends a tombstone; it does not physically erase stored content.
- LiteRT-LM is optional and disabled by default. Download and inference require separate explicit opt-ins; model output is untrusted text and cannot authorize or invoke tools.

## Critical limitations and residual risks

- **No OS-enforced sandbox or permission-granted tool executor exists.** The staging workspace is not a sandbox. No submitted or generated code may be executed. An OS-isolated execution backend, policy boundary, resource limits, filesystem/network restrictions and adversarial tests are prerequisites before any tool execution is introduced.
- **The interaction matrix is unpopulated.** Unknown pairs block or require human review. Empty impact results do not prove that no dependencies exist.
- **The canonical source catalogue is incomplete.** Capabilities 1–84 and meta-rules 1–15 were not supplied; missing source material is not fabricated. The six self-* domains are provisional operational domains, not canonical A–AN families.
- **The local witness is not a remote independent witness.** Cross-process locking protects cooperating local writers; it does not provide remote attestation, hardware-backed identity or protection against a privileged attacker controlling the host and witness key.
- **Local SQLite append-only triggers and local hash chains are not tamper-proof against an attacker with sufficient filesystem or database privileges.** Export critical evidence and keep trust anchors under separately controlled access.
- **A signature proves possession of a private key, not the real-world identity of its holder.** Key enrollment and public-key distribution require out-of-band verification.
- **A successful CI run is not a security review.** Signing a release manifest is an operator's explicit assertion that they personally reviewed and trust the exact commit and its build/test provenance. A compromised CI system or malicious change that passes tests remains a residual risk.
- **Memory tombstones hide records from normal retrieval but do not securely erase content from SQLite files, backups or filesystem storage.**
- **Formal model checking covers the documented lifecycle abstraction, not every Python runtime behavior, platform behavior or cryptographic implementation.**
- **Android Debian / Pixel 6 installation, sandbox availability and on-device model inference have not been verified by remote repository CI.**

## Required gates before expanding autonomy

1. Keep execution disabled until an OS-isolated sandbox and a permission-scoped executor have been independently reviewed and adversarially tested.
2. Populate interaction and dependency relationships only from reviewed, source-backed evidence; unknown relationships remain blocking.
3. Require explicit per-capability maturity evidence, human authorization and signed approvals. No self-promotion.
4. Treat remote witness deployment as a separate trust domain with independent operators, keys and retention.
5. Re-run platform-specific tests on the actual target device; GitHub CI does not establish Android device compatibility.



### Optional Litestar diagnostics API

The Litestar adapter is a local diagnostic surface only. The supported CLI
launcher binds Uvicorn to IPv4 loopback (\`127.0.0.1\`) and the app accepts only
loopback Host values. It has no write, approval, settings mutation, lifecycle
transition, tool-execution or network-egress handlers. The application
rejects a symlink/non-directory data root and uses existing read-only
diagnostic and SQLite accessors. Do not expose this listener through a proxy,
port-forward or LAN interface. Loopback binding is not a substitute for
operating-system process isolation or protection from other local processes.



The API's \`network_egress_route_enabled: false\` flag is descriptive of the
route set only. It is not a claim that the Python process or host operating
system cannot initiate network connections. Enforce process/host egress
restrictions separately when needed.



### Provider and model catalogue boundary

The provider registry is metadata-only. It exposes the one currently
source-backed provider adapter (LiteRT-LM text generation) and never
instantiates it. The model catalogue is strict and read-only: it rejects
unknown providers, unsupported formats/modalities, duplicate IDs, path
traversal and symlinked model roots/artifacts. Optional SHA-256 checks prove
only that the local file matches the operator-declared digest; they do not
establish publisher authenticity. No model entry is automatically loaded,
downloaded or executed, and no provider receives tool-execution authority.


### Backup snapshot boundary

The checked-file controls protect the backup and manifest leaf paths and bind verification to the bytes restored. They do not secure attacker-controlled parent directories, defend against a privileged process with access to the temporary directory, or establish off-device witness custody. Backup creation from a live registry remains a separate source-path and filesystem trust boundary.
