# Specification readiness

NEXORA exposes a read-only aggregate report for source coverage, the 264 × 264
interaction matrix, precedence integrity, and settings authorization readiness.

## CLI

```bash
nexora spec-status
nexora spec-status --catalog spec/capability_catalog.json --rules spec/meta_rules.json
nexora settings policy-status
```

`spec-status` returns exit code 0 only when the report has no outstanding
source, matrix, or settings-governance blockers. Exit code 3 means the artifacts
were readable but the project is not ready; exit code 2 means an artifact could
not be validated.

The report currently identifies missing capability IDs 1–84 and meta-rule IDs
1–15, counts declared versus unknown matrix pairs, and reports every current
setting as lacking approved per-setting authorization. These are reports of
the repository's current artifacts, not newly authored canonical definitions.

## Safety contract

- No missing capability or meta-rule is generated.
- No matrix relationship is inferred from family membership, numbering,
  symmetry, transitivity, or precedence.
- Declared matrix relationships remain review-only.
- A settings policy file's presence or contents do not constitute approval.
- No settings apply, rollback execution, policy mutation, or agent execution
  endpoint is introduced.
- L0 remains the default; scheduler, sandbox and network settings remain
  unchanged.

A future policy approval requires an owner-reviewed per-setting authorization
matrix and separately reviewed rollback procedure. Until then, settings
mutation remains unsupported.
