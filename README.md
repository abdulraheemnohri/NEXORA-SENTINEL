# NEXORA SENTINEL

Self-Terminal Autonomous Intelligence Platform · STA-264  
Autonomy Through Verifiability · v0.1.0 Safety Kernel Foundation

NEXORA Sentinel is a local-first safety and governance foundation. It is **not yet a completed autonomous agent**.

## Included
- Python package and CLI with fail-closed policy decisions.
- Persistent emergency stop and hash-chained local audit log.
- Sequential evidence-gated capability lifecycle.
- SQLite capability registry, terminal revocation and rollback decision records.
- Ed25519 approval receipts with explicit public-key pinning, scope binding, expiry and replay protection.
- Persistent action-budget ledger.
- Persistent scheduler that queues and claims due review jobs but never executes them.
- Tool proposal boundary; tools are recorded for review and never invoked.
- Staging workspace with path-containment checks; submitted code is never executed.
- Validated local configuration, read-only diagnostics, tests and CI.

## Important incomplete specifications
The supplied source records currently cover capabilities 85–264 (180 entries) and meta-rules 16–45 (30 entries). Original definitions 1–84 and 1–15 have not been provided. The 264×264 interaction matrix remains empty by design. Do not infer missing relations or fabricate source records. Until these gaps are resolved, `catalog-check` intentionally reports incomplete.

## Install (Debian / Android Debian)
```bash
bash scripts/install_android_debian.sh
.venv/bin/nexora status
```

## Verify
```bash
bash scripts/run_tests.sh
```

## CLI
```bash
nexora status
nexora catalog-check
nexora check ACTION --risk low
nexora audit
nexora kill
nexora resume
```

## Safety posture
Autonomy defaults to L0. Scheduler, sandbox and network feature flags default off. A proposal is not a mutation. A scheduled job is not permission to execute. Tool proposals are review-only. The staging workspace does not execute code. The Ed25519 module proves possession of a pinned key, not the real-world identity of its holder. The registry has not yet been wired to require signed receipts for APPROVED/ENABLED transitions.

## Planned, not yet delivered
Full TUI and web dashboard, model runtime, memory system, real sandbox isolation, controlled tool execution, self-evolution pipeline, complete capability catalogue and interaction matrix. No production execution capability is enabled in this milestone.

See [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), [operations](docs/OPERATIONS.md), and [project status](docs/PROJECT_STATUS.md).

License: Unlicense.
