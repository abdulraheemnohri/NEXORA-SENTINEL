# STA v1.0 Specification Reconciliation

Date: 2026-11-19  
Status: source-intake and gap analysis; no policy or runtime authority

## Purpose

This document records what the newly supplied **Self-Terminal AI (STA) v1.0 · Full System Charter** contributes to NEXORA-SENTINEL, compares it with the repository's source-backed catalogues, and identifies inconsistencies that must be resolved before implementation. The supplied charter is treated as design input, not as blanket authorization to enable autonomy, network access, model execution, settings mutation, or tool execution.

## What the supplied charter adds

- Target architecture: Litestar UI/API, immutable oversight kernel, Family AF interaction governance, Family W lifecycle orchestration, A–AN capability families, adapter bus, and substrate services.
- Named capability descriptions for families A–N, plus abbreviated names for O–AN that overlap the existing source-backed catalogue.
- Six cross-cutting capabilities: CC1 interrupt, CC2 restart, CC3 handoff, CC4 witness, CC5 rehearse, CC6 debrief.
- Proposed adapters: LiteRT-LM, Ollama, llama.cpp, vLLM, OpenAI, Anthropic, Google, and custom HTTP.
- Proposed UI pages, settings groups, observability stack, deployment topologies, and four roadmap phases.
- High-level governance principles: safety precedence, human approval for privilege expansion, default-deny execution/egress/replication, and a staged self-modification pipeline.

These are target requirements and proposed designs. They are not evidence that the corresponding code, dependencies, isolation controls, or operational qualification already exist.

## Catalogue arithmetic: unresolved discrepancy

The existing `spec/capability_catalog.json` contains 180 records for IDs 85–264. Those records include six cross-cutting entries. The supplied charter's newly listed A–N family counts are:

| Family | Listed capabilities |
|---|---:|
| A Cognitive | 6 |
| B Operational | 6 |
| C Social / Cooperative | 5 |
| D Knowledge & Memory | 4 |
| E Security | 4 (three numbered entries plus core Defending) |
| F Governance | 4 |
| G Temporal | 6 |
| H Affective / Motivational | 7 |
| I Creative | 5 |
| J Economic | 6 |
| K Embodied | 5 |
| L Evolutionary | 6 |
| M Epistemic | 8 |
| N Existential | 5 |
| **A–N total** | **73** |

The charter says the system contains 264 capabilities, but the newly supplied A–N list contains 73, not 84. The existing catalogue has 180 records for 85–264; adding the 73 A–N entries gives 253, leaving **11 capability definitions unaccounted for**. The six cross-cutting records are already included in the existing 180-record range and must not be double-counted.

No IDs 1–84 have been assigned from this charter. Family order is not an authoritative capability-ID mapping. The 11-entry discrepancy must be resolved from the source owner before the catalogue can be completed.

## Meta-rule gap remains open

The charter states that there are 45 meta-rules but does not enumerate their IDs, titles, or normative text. The repository currently contains 30 source-backed rules (16–45); rules 1–15 remain missing. General principles in the charter are not silently converted into the missing 15 rules because their exact scope, exceptions, precedence, and enforcement semantics are unspecified.

## Interaction governance

The charter gives one high-level precedence statement: **Safety > Governance > all other families**. This is useful as a candidate invariant, but it does not define the 264 × 264 pairwise relation set, conflict semantics, directionality, exceptions, composition rules, or evidence required to approve a relation.

The machine-readable interaction matrix therefore remains unpopulated. Unknown relations continue to deny composition or require human review. No family-level or capability-level matrix entries are inferred from family names or this single precedence statement.

## Settings and autonomy: design proposal, not approval

The supplied example configuration proposes global autonomy level 2, Family A autonomy 3, and Family AF autonomy 4. Those values conflict with the repository's conservative L0/L1 settings boundary and are not adopted as active defaults.

The following remain disabled or unimplemented until their security contracts are specified and reviewed: model serving, online adapters, egress, shell, sandbox execution, tool execution, capability promotion, remote administration, autonomous self-modification, and network downloads. A settings file or UI control cannot override the immutable policy kernel.

The charter's settings precedence (per-capability → per-family → global → immutable policy kernel) is recorded as a proposed resolution order only. The policy kernel must always be the final authority. Per-setting authorization, promotion evidence, rollback, key revocation, and recovery semantics still require owner-approved rules.

## Architecture decisions still required

1. **Local-first storage versus production services.** The charter names PostgreSQL and Redis for production, while the existing foundation is SQLite/local-first. Define supported profiles and migration/backup semantics before adding mandatory infrastructure.
2. **Litestar and admin stack.** Select exact supported versions and a minimal dependency set; define authentication, RBAC, session storage, CSRF, audit hooks, and loopback binding before mounting an admin interface.
3. **Runtime contract.** Verify the actual supported LiteRT-LM Python and server interfaces against the pinned version. The charter's illustrative API is not treated as a tested contract.
4. **Adapter trust.** Define secret handling, endpoint allowlists, TLS policy, data egress classification, cost ceilings, timeout/retry policy, and fallback rules. No API keys or online calls are enabled by this document.
5. **Sandbox.** Select and qualify an OS-enforced backend per platform. A preflight check or staging directory is not a sandbox. Tool execution remains disabled until isolation, resource limits, filesystem/network policy, and escape testing exist.
6. **Memory embeddings.** Define model provenance, offline installation, vector-index rebuild, deletion/tombstone semantics, and provenance preservation before enabling semantic retrieval.
7. **Autonomy maturity.** The charter names L0–L4 but does not supply objective per-level promotion criteria for every capability. No automatic mapping from lifecycle states to L0–L4 is assumed.
8. **Witness independence.** A separate local process is not equivalent to a remote host, hardware-backed key, or independently administered witness. These assurance levels must remain distinct in reporting.

## Implementation disposition

| Workstream | Disposition |
|---|---|
| Preserve the supplied charter and reconcile its counts | Documented here |
| Capabilities 1–84 | **Blocked:** 11 definitions remain unaccounted for; exact ID mapping is absent |
| Meta-rules 1–15 | **Blocked:** normative source text not supplied |
| 264 × 264 interaction matrix | **Blocked:** pairwise relationships not supplied |
| Litestar API/UI | Architecture target only; implementation and security design required |
| LiteRT-LM and other adapters | Existing adapter status must be checked against pinned upstream APIs; no new adapter is enabled by this charter |
| OS sandbox and tool execution | **Blocked:** platform isolation and execution threat model required |
| Semantic memory | Design/qualification required; lexical memory remains authoritative |
| Settings authorization and rollback | **Blocked:** owner-approved policy matrix required |
| Android/Pixel and Windows 10 qualification | Physical-device testing remains outstanding |

## Acceptance criteria for closing this reconciliation

- A source owner supplies the missing 11 capability definitions and authoritative IDs, or formally revises the stated total and scope.
- The 45 meta-rules are supplied as individually numbered, normative records with provenance.
- The interaction matrix has reviewed, versioned entries and explicit unknown/conflict behavior.
- Per-setting authorization, autonomy promotion, and rollback policies are approved independently of the model/runtime.
- Each implementation increment has tests, threat-model updates, and exact-head CI evidence. Physical platform claims are made only after actual device qualification.

**Bottom line:** STA v1.0 substantially clarifies the intended destination, but it is not yet a complete machine-executable specification. This reconciliation intentionally preserves the missing-source boundary and prevents a design example from being mistaken for authorization.



## Follow-on implementation: source validator

A read-only \`nexora spec-validate\` command now validates the current source
artifacts' record shapes and declared gaps. It also requires every future
interaction pair to carry a source reference and SHA-256 evidence fingerprint.
This is a structural/provenance contract only: it does not create missing
definitions or relationships, authenticate an external source, or authorize
any capability. See \`docs/SPEC_VALIDATION.md\`.
