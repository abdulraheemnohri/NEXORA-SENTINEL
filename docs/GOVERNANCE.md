# Governance

## Priority order

SAFETY > GOVERNANCE > OPERATIONAL > CONVENIENCE. Unknown and equal-priority conflicts are blocked for human review.

## Interaction matrix

The matrix is 264×264. Its current entries are empty because the source relationships have not been provided. A missing cell is returned as `BLOCK_AND_ESCALATE`, never as compatible or safe.

## Approval

APPROVED and ENABLED lifecycle transitions require a signed Ed25519 receipt from an explicitly enrolled key. Receipts bind capability ID, transition, evidence digest, approver label, expiry and nonce. A cryptographic signature proves possession of the enrolled key; it does not establish the holder's real-world identity.

## Autonomy

The default autonomy level is L0. Scheduling, network access, sandbox execution and tool execution remain disabled. A scheduled item is a review task, not an execution grant.
