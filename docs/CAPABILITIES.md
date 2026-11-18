# Self-capability catalogue and control plane

NEXORA defines a target of 264 self-capabilities across 40 families (A–AN), plus 45 meta-rules and cross-cutting governance layers. The checked-in source data currently contains 180 capability records (IDs 85–264) and 30 meta-rules (IDs 16–45). Original definitions 1–84 and rules 1–15 are not present in the checked-in source. The report exposes these gaps; it does not invent names, descriptions, evidence, gates, dependencies or pairwise interactions.

## Inspect coverage

```bash
nexora capabilities
nexora capabilities --family W --include-records
```

The command is read-only. The local dashboard exposes the same report at `/api/self-capabilities`.

## Capability lifecycle

`SPECIFIED → REGISTERED → IMPLEMENTED → TESTED → SHADOWED → APPROVED → ENABLED`

A catalogue record means specified, not implemented or executable. Registry lifecycle transitions remain evidence-gated. Approval and enablement require the existing signed, scoped, unexpired, single-use approval receipt. Model output cannot promote a capability or mutate policy.

## Interaction governance

The 264×264 matrix remains unpopulated. Unknown relations stay unknown and must be denied or sent for human review. No dependency, conflict, reinforcement, composition or precedence relation is inferred from IDs or family labels.

## Self-family proposal boundary

Self-family proposal records remain immutable, append-only review artifacts. Submission or human review does not authorize execution, policy changes, capability promotion or tool invocation. Execution is disabled.
