# Governance

## Priority order

SAFETY > GOVERNANCE > OPERATIONAL > CONVENIENCE. Unknown and equal-priority conflicts are blocked for human review.

## Interaction matrix

The matrix is 264×264. Its current entries are empty because the source relationships have not been provided. A missing cell is returned as `BLOCK_AND_ESCALATE`, never as compatible or safe.

## Approval

APPROVED and ENABLED lifecycle transitions require a signed Ed25519 receipt from an explicitly enrolled key. Receipts bind capability ID, transition, evidence digest, approver label, expiry and nonce. A cryptographic signature proves possession of the enrolled key; it does not establish the holder's real-world identity.

## Autonomy

The default autonomy level is L0. Scheduling, network access, sandbox execution and tool execution remain disabled. A scheduled item is a review task, not an execution grant.


## Governance validation

Run a read-only contract check:

```bash
nexora governance-check
```

Inspect one directed relationship exactly as declared:

```bash
nexora governance-relation 85 86
```

The validator checks the 264×264 matrix dimensions, ID range, relation vocabulary,
duplicate directed pairs, and fixed precedence contract. An empty matrix is reported
as `UNPOPULATED_BLOCKING`; an undeclared pair returns `BLOCK_AND_ESCALATE`.
A declared relation is only `REVIEW_REQUIRED`, never an automatic compatibility
grant. Reverse edges, symmetry, transitive closure, and family-based compatibility
are never inferred.

The loopback read-only dashboard exposes the same report at
`/api/governance`. These diagnostics do not mutate governance files, lifecycle
state, policy, or runtime configuration.
