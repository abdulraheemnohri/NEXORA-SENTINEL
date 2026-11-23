# Exact-source recovery and import preview

Run the diagnostic:

    nexora source-status

The report lists missing capability IDs from the 264-entry target catalogue and
missing meta-rule IDs from the 45-rule target. Missing definitions must be
recovered from the original source; they must not be invented.

## Preview an exact-source artifact

Create a UTF-8 JSON artifact containing a non-empty `capabilities` or `rules`
array. Capability records require `id`, `name`, `family`, `family_name`,
`status`, and `source`. Meta-rule records require `id`, `title`, `text`,
`status`, and boolean `mutable_by_agent`.

Examples:

    nexora source-import-preview recovered-capabilities.json --kind capability --source-ref "Original Addendum I, page 4"
    nexora source-import-preview recovered-rules.json --kind meta-rule --source-ref "Original specification, rules 1-15"

Optional `--catalog` and `--rules` flags allow checking against explicitly
selected canonical files. The preview checks required fields, ID ranges,
duplicate candidate IDs, collisions with existing IDs, family/status values,
and source reference. It sorts candidates by ID and includes the artifact
SHA-256 so a reviewer can identify exactly what was inspected.

## Safety boundary

This command is preview-only. It does not write canonical JSON, record approval,
change lifecycle state, mutate policy, or enable execution. A preview is not
approval. A human must compare every record with the original source and a
separately audited approval/import process is still required. The missing
capability definitions 1-84 and meta-rules 1-15 remain missing until the
original source text is supplied and reviewed.


## Prior-conversation source pointers checked 2026-11-20

A prior-conversation context lookup identified two original user-supplied
sections from the Self-Terminal AI specification discussion on 2026-11-18
(approximately 05:21:25 UTC):

- **Self-Terminal AI: Expanded Self-Capability Set** — capability IDs 1–28 and
  meta-rules 1–8.
- **Self-Terminal AI: Extended Capability Set (Addendum II)** — capability IDs
  29–84 and meta-rules 9–15.

This confirms that the original source sections existed in the earlier
conversation. However, the available retrieval returned only the headings,
ranges and a summary of their contents, not the complete original message
bodies. A separate Library search did not locate an exact source artifact.
Therefore no capability or meta-rule records have been imported from memory,
summaries or inferred wording.

**Blocking input:** provide an export, attachment or exact text of those two
original sections. Once available, compare every record to the source, run
`nexora source-import-preview`, record the source hash and review evidence,
and only then prepare a separately reviewed import. The current preview path
does not itself approve or mutate the canonical catalogue.


## Targeted conversation retrieval excerpts — 2026-11-22

Source: the user's original message at approximately 2026-11-18 05:21:25 UTC,
titled **Self-Terminal AI: Expanded Self-Capability Set**, followed by
**Self-Terminal AI: Extended Capability Set (Addendum II)**. The excerpts below
were returned by targeted conversation-linked retrieval. Preserve them as
source excerpts; do not treat this incomplete note as the full specification.

### Capability excerpts

1. **Self-Explaining** — Generates human-readable rationales for its actions,
   plans, and self-modifications. · Mechanism: causal trace capture +
   counterfactual generation ("what would I have done without X?"). · Gate:
   explanation must match the actual decision path (consistency check against
   audit log). · Why it matters: auditability, trust, and a signal for detecting
   deception/drift.

2. **Self-Critiquing** — Evaluates its own outputs and plans before committing
   them. · Mechanism: critic model / adversarial self-review; rubric-based
   scoring; "red-team yourself" pass. · Output: accept / revise / escalate. ·
   Gate: critic is a separate model instance so it can't collude with the
   generator.

3. **Self-Correcting** — Detects and repairs its own errors post-hoc. ·
   Mechanism: outcome monitoring vs. intent; automatic rollback of bad actions;
   error taxonomy that feeds learning. · Gate: corrections to irreversible
   actions require human approval.

4. **Self-Calibrating** — Keeps its confidence estimates honest. · Mechanism:
   reliability diagrams, temperature scaling, abstention policies, OOD
   detection. · Gate: calibration drift beyond threshold triggers retraining
   proposal.

5. **Self-Prioritizing** — Ranks goals/tasks by value, urgency, cost, and risk. ·
   Mechanism: utility model + constraint solver; explicit trade-off logging. ·
   Gate: cannot override top-level human goals.

6. **Self-Reflecting** — Periodic meta-review of its own behavior over time. ·
   Mechanism: scheduled "retrospective" passes over logs → insights →
   learning/growth proposals. · Gate: reflections are proposals, never direct
   actions.

The retrieval also identified names for items 7–10 as Self-Healing,
Self-Optimizing, Self-Scaling and Self-Scheduling, but did not return their
complete original descriptions, mechanisms or gates in that query. They are
not reconstructed here.

### Meta-rule excerpt

1. **Proposal, not mutation.** Every self-change is a proposal routed through
   the validation pipeline (static check → sandbox → shadow → canary → promote).

### Completeness and import gate

This is a partial transcription, not a canonical source artifact. The exact
full text for capability definitions 1–84 and meta-rules 1–15 has not yet been
assembled and independently checked against the original user message.
Definitions 7–84 and meta-rules 2–15 remain incomplete in this note. Do not
create canonical records, infer omitted clauses, or populate unknown
interaction-matrix cells from these fragments. Once the full original text is
available, compare each record to it, hash the source artifact, and use the
preview-only import workflow before any separately approved canonical import.


## Additional conversation-linked source search — 2026-11-23

A further prior-conversation retrieval identified a separate user message titled
**Self-Terminal AI — Complete Project Specification** (around 2026-11-18
05:02:54 UTC), described in the retrieval result as containing 264 capability
entries and 45 meta-rules. The retrieval did **not** return its verbatim body,
and did not establish that its wording is identical to the two specifically
requested sections:

- **Self-Terminal AI: Expanded Self-Capability Set** (IDs 1–28; meta-rules 1–8)
- **Self-Terminal AI: Extended Self-Capability Set (Addendum II)** (IDs 29–84; meta-rules 9–15)

A second targeted retrieval for the complete specification's exact text returned
no matching conversation. A Library search for the exact titles and distinctive
phrases returned no matching specification artifact. Therefore the separate
264-capability/45-rule reference is a source lead only; it is not a substitute
for the exact 1–84 / 1–15 source set and has not been imported.

The partial excerpts for capabilities 1–6 and meta-rule 1 recorded above remain
partial excerpts from the earlier targeted retrieval. They are not a complete
source artifact and do not authorize canonical import. No definitions,
mechanisms, gates, meta-rules or interaction-matrix cells have been inferred.
