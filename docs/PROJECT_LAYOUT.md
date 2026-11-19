# Project Layout

- `src/nexora/`: application package and safety/governance modules.
- `src/nexora/self_families.py`: provisional proposal-only self-* domains and settings.
- `src/nexora/self_family_store.py`: durable SQLite proposal records and append-only review history; no execution or approval authority.
- `src/nexora/storage/migrations/`: versioned SQLite migration and recovery utilities.
- `tests/`: unit and safety regression tests.
- `spec/`: source-backed capability catalogue, meta-rules and interaction matrix; known source gaps are documented.
- `docs/`: architecture, threat model, operations and project status.

The TUI, stdlib web dashboard and optional loopback-only Litestar diagnostics API are implemented as read-only surfaces. LiteRT-LM inference exists only through its explicit-confirmation CLI adapter. An OS-enforced execution sandbox and automatic provider/tool execution remain future work.


- `litestar_api.py`: optional GET-only loopback diagnostics API. The stdlib dashboard remains the default local UI.


- `intelligence/provider_registry.py`: deterministic, metadata-only adapter registry.
- `intelligence/model_catalog.py`: strict read-only model manifest and artifact integrity checks.
