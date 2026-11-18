# Exact-source recovery status

Run:

    nexora source-status
    nexora source-status --catalog spec/capability_catalog.json --rules spec/meta_rules.json

The report lists missing capability IDs from the 264-entry target catalogue and
missing meta-rule IDs from the 45-rule target. A missing ID is a source recovery
task, not permission to invent a title, description, family assignment, gate,
or interaction.

## Import requirements

Any future import must preserve exact source wording and record its source
label or document reference. Existing IDs must not be overwritten. Duplicate
IDs must be rejected. A human must review proposed changes before the canonical
catalogue is updated.

This command is diagnostic only. It does not import records, mutate policy,
change capability lifecycle state, or enable execution.
