# NEXORA SENTINEL

Self-Terminal Autonomous Intelligence Platform · STA-264  
Autonomy Through Verifiability. · v0.1.0 Safety Kernel Foundation

This is a safety-governed, local-first foundation, not a completed autonomous agent. The exact source specification for the 264 capabilities and 45 numbered meta-rules must be imported verbatim. Missing definitions are not fabricated.

## Foundation delivered
- Python package and nexora CLI
- Fail-closed policy kernel; unknown actions denied
- Persistent emergency kill switch
- SHA-256 hash-chained JSONL audit log
- Separate local witness receipts
- Capability catalog completeness gate and 264×264 matrix schema
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
- spec/capability_catalog.json: exact 264 IDs/names, 40 families A–AN, gates, metrics, failure modes and autonomy ceilings.
- spec/meta_rules.json: all 45 exact numbered rules.
- spec/interaction_matrix.json: specified relations only; unknown remains unknown.

Until imported, catalog-check exits non-zero intentionally. See docs/ARCHITECTURE.md and docs/THREAT_MODEL.md.

License: Unlicense.
