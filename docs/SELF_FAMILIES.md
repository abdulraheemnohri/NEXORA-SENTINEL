# Self-* Capability Domains

This module introduces six **provisional operational domains**. They are not the canonical A–AN specification families and do not claim to fill missing catalogue entries.

| Domain | Default | Permitted output |
|---|---:|---|
| Self-observation | On | Read-only local snapshot |
| Self-diagnostics | On | Evidence-linked finding |
| Self-repair planning | Off | Reversible repair proposal |
| Self-learning | Off | Provenance-linked untrusted knowledge candidate |
| Self-governance assistance | Off | Policy explanation; no policy mutation |
| Self-evolution | Off | Staged change proposal; no promotion |

## Settings

`SelfFamilySettings` provides one explicit enable flag per domain and an autonomy level restricted to L0/L1. Observation and diagnostics are enabled by default; all domains that can influence future behavior are disabled by default.

## Safety contract

- This API creates deterministic review proposals only.
- No proposal executes a tool, writes project files, changes trusted memory, modifies policy, or changes lifecycle state.
- No self-family can enable itself or another family.
- Proposals remain `PENDING_HUMAN_REVIEW` and `execution=DISABLED`.
- Enabling a proposal-producing domain only permits proposal generation; it does not grant execution authority.
- Signed approvals, policy checks, budget checks, lifecycle evidence and independent review remain separate required controls.
- These domains do not substitute for the missing original source definitions for capability IDs 1–84 or meta-rules 1–15.

## Example

```python
from nexora.self_families import SelfFamily, SelfFamilyManager, SelfFamilySettings

manager = SelfFamilyManager(
    SelfFamilySettings(evolution_enabled=True)
)
proposal = manager.propose(
    SelfFamily.EVOLUTION,
    "Propose a bounded diagnostics refactor",
    evidence=("review-ticket:123",),
    payload={"scope": "diagnostics"},
)
assert proposal.execution == "DISABLED"
```

The example does not modify the repository or activate code. A separate, independently authorized workflow must review and validate any proposed change.
