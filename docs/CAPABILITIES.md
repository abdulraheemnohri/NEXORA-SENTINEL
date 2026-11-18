# Capability catalogue

The intended catalogue contains 264 capabilities across 40 canonical families (A–AN) and three cross-cutting layers. The current source file includes 180 records, IDs 85–264. Original definitions for IDs 1–84 have not been supplied.

The loader accepts only explicit records and rejects duplicate IDs. It does not generate descriptions, gates, dependencies or source provenance. The SQLite registry is lifecycle metadata and does not invoke implementations.

Capability lifecycle:

`SPECIFIED → REGISTERED → IMPLEMENTED → TESTED → SHADOWED → APPROVED → ENABLED`

Transitions are sequential and evidence-gated. APPROVED and ENABLED require a signed, scoped, unexpired, single-use approval receipt. Revocation is terminal in the current schema.

See `spec/capability_catalog.json` for supplied source data. Do not infer missing definitions.
