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
