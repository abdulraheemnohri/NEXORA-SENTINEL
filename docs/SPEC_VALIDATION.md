# STA Source Specification Validation

## Purpose

\`nexora spec-validate\` performs read-only structural validation of the
canonical capability catalogue, meta-rule catalogue, interaction matrix and
precedence artifact. It is deliberately separate from \`nexora spec-status\`:

- \`spec-validate\` asks whether the existing source files are structurally
  coherent and carry required provenance.
- \`spec-status\` asks whether the full source, interaction matrix and
  settings-authorization requirements are ready.

A structurally valid partial catalogue is expected to pass validation while
remaining blocked for project completion.

## Command

    nexora spec-validate

Optional file overrides are available for controlled testing and review:

    nexora spec-validate \
      --catalog path/to/capability_catalog.json \
      --rules path/to/meta_rules.json \
      --matrix path/to/interaction_matrix.json \
      --precedence path/to/precedence.json

Exit codes: 0 means the supplied artifacts are structurally valid; 2 means
one or more artifacts are malformed or cannot be safely read. A valid partial
source returns exit 0 with status \`VALID_PARTIAL_BLOCKED\`. This is not a
readiness or authorization result.

## Validation contract

### Capability catalogue

Each record must have an integer (not Boolean) ID in 1–264, a non-empty name,
a canonical A–AN family code or CROSS-CUTTING, a non-empty family label,
a known status and a non-empty source reference. Duplicate IDs, conflicting
family names, invalid fields and incorrect declared missing ranges fail.

A catalogue declaring itself complete must cover all 264 IDs and all 40
canonical family codes. Partial catalogues may report missing ranges and
families; the validator does not fill them.

### Meta-rules

Each rule must have a unique integer ID in 1–45, a non-empty title and exact
text, a non-empty status and \`mutable_by_agent: false\`. The declared missing
ranges must match the actual missing IDs. A complete declaration must cover
all 45 records.

### Interaction matrix

The matrix must retain dimensions 264 × 264, IDs 1–264, the fixed relation
vocabulary, \`default_relation: unknown\` and the fail-closed unknown-relation
policy. The declared precedence sequence must remain Safety, Governance,
then all other capabilities.

Every populated pair must be directed and unique, reference two capability
IDs that already exist in the source-backed catalogue, and include:

- \`source\`: integer source capability ID.
- \`target\`: integer target capability ID.
- \`relation\`: one of the six declared relation types.
- \`source_ref\`: a non-empty source document/section/revision reference.
- \`evidence_sha256\`: a lowercase SHA-256 digest of the evidence artifact.

Reverse edges, symmetry, transitive relationships and compatibility grants
are never inferred. Every pair remains subject to separate governance review.
The validator reports unknown pair count; it does not mark unknown pairs safe.

### Precedence

The separately stored precedence artifact must retain the immutable ordering
SAFETY > GOVERNANCE > OPERATIONAL > CONVENIENCE, block-and-escalate behavior
for unknown/equal-priority conflicts and \`mutable_by_agent: false\`.

## Safety and limitations

The validator rejects symlinks, non-regular files, duplicate JSON object keys,
oversized files and malformed UTF-8/JSON. It does not write or initialize any
file. It does not import candidates, verify that cited source documents are
authentic, verify the evidence hash against an external artifact, authorize a
relationship, approve settings, activate a capability or enable execution.

A \`VALID_COMPLETE_REQUIRES_INDEPENDENT_REVIEW\` report is still not a
production-readiness declaration. Independent source review, settings
authorization, rollback policy, sandbox qualification and all operational
acceptance tests remain separate gates.
