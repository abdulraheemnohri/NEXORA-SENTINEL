# API and package map

This release exposes a Python package and CLI. Stable public import surfaces include:

- `nexora.core`: proposal planning and lifecycle APIs.
- `nexora.oversight`: policy, audit, kill switch, witness and approval gateway.
- `nexora.governance`: precedence and unknown-safe interaction lookup.
- `nexora.capabilities`: immutable source records and persistent registry.
- `nexora.runtime`: staging, resource budgets and proposal-only tool bus.
- `nexora.intelligence`: local model inventory and output evaluation contracts.
- `nexora.memory`: bounded session memory, SQLite records and provenance.
- `nexora.evolution`: proposal, validation, shadow and canary gates.
- `nexora.terminal`: restricted command parsing and output sanitation.

CLI commands: `status`, `catalog-check`, `check`, `audit`, `kill`, `resume`, `registry-init`, `backup`, `verify-backup`, `restore`.

Backup workflow: initialize the registry with `nexora registry-init`, create a snapshot with `nexora backup`, verify it with `nexora verify-backup PATH`, and restore to a new destination with `nexora restore BACKUP DESTINATION`.

No HTTP API is currently exposed. No runtime execution API is enabled.
