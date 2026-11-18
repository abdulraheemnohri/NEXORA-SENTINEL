# NEXORA SENTINEL

Self-Terminal Autonomous Intelligence Platform · STA-264  
Autonomy Through Verifiability. · v0.1.0 Safety Kernel Foundation

This is a safety-governed, local-first foundation, not a completed autonomous agent. The specification now records capabilities 85–264 (180 entries), meta-rules 16–45 (30 entries), and a 264×264 interaction-matrix schema. Earlier capabilities 1–84 and rules 1–15 remain unregistered because their source definitions have not yet been supplied.

## Foundation delivered
- Python package and nexora CLI
- Fail-closed policy kernel; unknown actions denied
- Persistent emergency kill switch
- SHA-256 hash-chained JSONL audit log
- Separate local witness receipts
- Capability registry with Addenda III–V entries 85–264, including mechanism and gate metadata for 216–264
- Meta-rules 16–45; immutable-to-agent flags
- 264×264 interaction-matrix schema (relations intentionally unpopulated)
- Tests, GitHub Actions CI, Android Debian install script

## Not enabled
The 264 capabilities, 45-rule catalogue, populated interaction matrix, scheduler, budgets, sandbox, model runtime, memory, tool bus, self-evolution pipeline, TUI and web dashboard are not yet implemented.

## Install (Debian / Android Debian)
Run: bash scripts/install_android_debian.sh  
Then: .venv/bin/nexora status  
Tests: bash scripts/run_tests.sh

## Commands
- nexora status
- nexora catalog-check
- nexora check ACTION --risk low
- nexora audit
- nexora kill
- nexora resume

## Safety invariants
Safety outranks all other priorities. Unknown actions/interactions are denied or reviewed. Autonomy defaults to L0. A proposal is not a mutation. Privilege expansion requires human approval. Audit integrity failure blocks appends. No generated code executes in this milestone. A local hash chain is tamper-evident, not tamper-proof.

## Specification import gate
- spec/capability_catalog.json: 180 registered entries (85–264); IDs 1–84 remain missing. Addendum V includes mechanism and gate fields for 216–264.
- spec/meta_rules.json: 30 registered rules (16–45); rules 1–15 remain missing.
- spec/interaction_matrix.json: 264×264 dimensions; relations remain unpopulated and unknown by default.

Until imported, catalog-check exits non-zero intentionally. See docs/ARCHITECTURE.md and docs/THREAT_MODEL.md.

License: Unlicense.
