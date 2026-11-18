# Conflict arbitration (proposal-only)

The governance arbitration API composes three existing controls:

1. The exact directed interaction-matrix cell must explicitly declare
   `conflicts`. Unknown cells and every other relation block arbitration.
   No reverse edge, symmetry, family membership, or inferred conflict is used.
2. The fixed precedence contract is SAFETY > GOVERNANCE > OPERATIONAL >
   CONVENIENCE. Unknown or equal priorities block and escalate.
3. A supplied wait-for graph is checked for cycles. A cycle or unknown node
   blocks the arbitration result.

## CLI

```bash
nexora governance-arbitrate 85 86 \
  --left-priority SAFETY \
  --right-priority OPERATIONAL \
  --wait-graph data/governance/wait_graph.json
```

The wait graph is a JSON object mapping each known node to a list of known
dependency nodes. Omit `--wait-graph` only when there are no declared waits.
Unknown dependency nodes are errors that block the decision.

## Decision semantics

- `BLOCK_AND_ESCALATE`: relationship, priority, or wait graph is unknown,
  invalid, equal-priority, or deadlocked.
- `PRECEDENCE_WINNER_PROPOSED_REVIEW_REQUIRED`: a declared conflict has a
  strict fixed-priority winner and no declared wait-graph cycle was found.

Even the second result is not permission to execute, suppress, cancel, schedule,
or mutate either proposal. It only identifies a candidate winner for independent
human review. The function always returns `proposal_authorized=false`,
`execution_enabled=false`, and `lifecycle_mutation=false`.

## Maturity boundary

The repository's existing evidence-gated lifecycle (SPECIFIED through ENABLED)
remains the authoritative promotion gate. A separate L0–L4 maturity scale has
not yet been supplied with canonical definitions and evidence thresholds.
NEXORA will not invent those criteria or silently map lifecycle states to L0–L4.
Until source-backed definitions are available, L0–L4 maturity claims remain
unimplemented; lifecycle evidence evaluation stays read-only and automatic
promotion remains disabled.
