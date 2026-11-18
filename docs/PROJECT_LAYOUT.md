# Project layout

```text
NEXORA-SENTINEL/
├── .github/workflows/ci.yml
├── config/default.json
├── docs/ (architecture, threat model, operations, status, layout)
├── scripts/ (Android Debian installer, tests, verification)
├── spec/ (capability catalogue, meta-rules, interaction matrix)
├── src/nexora/ (policy, lifecycle, registry, approvals, budgets, scheduler,
│                tool boundary, staging workspace, config, diagnostics, CLI)
└── tests/ (core governance and platform service tests)
```

The scheduler only claims due jobs; it does not run them. The tool boundary only stores proposals. The staging workspace never executes code. Feature flags default off. No web dashboard, TUI, model runtime, or autonomous execution is claimed in this milestone.
