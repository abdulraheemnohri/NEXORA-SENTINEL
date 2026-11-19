# Project Layout

- `src/nexora/`: application package and safety/governance modules.
- `src/nexora/self_families.py`: provisional proposal-only self-* domains and settings.
- `src/nexora/self_family_store.py`: durable SQLite proposal records and append-only review history; no execution or approval authority.
- `src/nexora/storage/migrations/`: versioned SQLite migration and recovery utilities.
- `tests/`: unit and safety regression tests.
- `spec/`: source-backed capability catalogue, meta-rules and interaction matrix; known source gaps are documented.
- `docs/`: architecture, threat model, operations and project status.

The TUI, web dashboard, API, model inference and OS-enforced sandbox remain future work.


- `litestar_api.py`: optional GET-only loopback diagnostics API. The stdlib dashboard remains the default local UI.
