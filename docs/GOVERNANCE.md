# Governance

## Priority order

SAFETY > GOVERNANCE > OPERATIONAL > CONVENIENCE. Unknown and equal-priority conflicts are blocked for human review.

## Interaction matrix

The matrix is 264×264. Its current entries are empty because the source relationships have not been provided. A missing cell is returned as `BLOCK_AND_ESCALATE`, never as compatible or safe.

## Approval

APPROVED lifecycle transitions require a signed Ed25519 receipt from an explicitly enrolled key. ENABLED transitions require at least two receipts from distinct enrolled signing keys and distinct approver IDs (maximum five). Every receipt binds the same capability ID, transition, evidence digest, its approver ID, expiry and nonce. All nonces are consumed in the same SQLite transaction as the lifecycle transition; a failure rolls back every receipt consumption. A cryptographic signature proves possession of the enrolled key; it does not establish the holder's real-world identity. The local trust store cannot independently prove that two keys are controlled by two different people.

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


## Two-person enablement approval

Create a separate keypair for each operator and enroll both public keys after
out-of-band fingerprint verification. Each operator issues their own receipt
for the same capability, transition and evidence set:

```bash
nexora approval issue --private-key operator-1.pem --capability-id 42 \
  --transition ENABLED --evidence human_approval rollback_plan monitoring_plan \
  --approver-id operator-1 --output operator-1-approval.json

nexora approval issue --private-key operator-2.pem --capability-id 42 \
  --transition ENABLED --evidence human_approval rollback_plan monitoring_plan \
  --approver-id operator-2 --output operator-2-approval.json

nexora registry-transition 42 ENABLED \
  --evidence human_approval rollback_plan monitoring_plan \
  --approver-id operator-1 operator-2 \
  --approval-receipt operator-1-approval.json operator-2-approval.json
```

The registry rejects one receipt, repeated approver IDs, repeated signing keys,
scope/evidence mismatches, expired or revoked keys, and replayed receipts.
Receipt consumption and state change are atomic. This is a two-key/two-label
control, not proof of two distinct humans; independent identity verification
and key custody remain operational requirements.
