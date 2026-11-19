# Evidence Freshness Intelligence

Evidence Freshness Intelligence is a read-only view over the append-only capability evidence ledger.

## Explicit expiry only

Evidence ledger schema v3 adds nullable `expires_at`. It is optional when a record is created:

```bash
nexora evidence add 85 \
  --type test_report \
  --reference artifact://reports/test-85.json \
  --sha256 <64-character-lowercase-sha256> \
  --operator operator-1 \
  --expires-at 2027-01-01T00:00:00Z \
  --confirm
```

The timestamp must be timezone-aware ISO-8601. It is normalized to UTC and included in the evidence record's canonical hash. Evidence records remain append-only. No expiry is inferred from `created_at`, evidence type, capability state, or external source.

Legacy records and new records without an expiry are `UNKNOWN`. The report does not treat UNKNOWN as valid or expired. `CURRENT` means only that an explicitly declared expiry has not passed. `EXPIRED` means that declared boundary has passed. An invalid timestamp is `INVALID_METADATA`. If the evidence hash chain fails, records are `UNVERIFIED` regardless of expiry.

## Interfaces

- CLI: `nexora evidence freshness [--capability-id 85]`
- Web dashboard: `/api/evidence-freshness` and `/api/evidence-freshness?capability_id=85`
- Terminal dashboard: option 5, Evidence freshness
- Evidence creation: `nexora evidence add ... --expires-at <timezone-aware-ISO-8601>`

The dashboard and report are read-only. They do not infer missing required evidence, revoke evidence, delete records, change lifecycle state, grant authorization, or execute tools. Reports are bounded to 500 records; `complete=false` and `DISPLAY_LIMIT_REACHED` disclose when more records exist.

## Migration and trust limitations

Writable ledger initialization adds the nullable column without rewriting legacy record hashes. Legacy records retain their original schema version and hash representation. Read-only views support legacy ledgers that have not yet acquired the new column; those records have no expiry and therefore report UNKNOWN. An operator must open the ledger through a writable application path to migrate its schema before creating v3 evidence records.

An expiry is an operator assertion, not an externally verified source policy. This feature does not supply canonical expiry rules, verify whether an external source has changed, or establish semantic correctness of an artifact.


## Evidence provenance intelligence v2

Evidence ledger schema v4 adds optional operator-declared fields:

- `source_uri`: source repository, publisher, or origin reference.
- `source_revision`: commit ID, immutable version, or other revision label.
- `collected_at`: optional timezone-aware collection timestamp.

Example:

```bash
nexora evidence add 85 \
  --type implementation_reference \
  --reference git:commit/0123456789abcdef \
  --sha256 <64-character-lowercase-sha256> \
  --operator operator-1 \
  --source-uri https://github.com/example/project \
  --source-revision 0123456789abcdef \
  --collected-at 2026-11-19T10:00:00+05:00 \
  --confirm

nexora evidence provenance
nexora evidence provenance --capability-id 85
```

The provenance report distinguishes `DECLARED_COMPLETE` (source URI and revision both supplied), `DECLARED_PARTIAL` (some provenance fields supplied), `UNDECLARED` (none supplied), and `UNVERIFIED` (ledger chain integrity failed). These labels describe metadata completeness, not authenticity.

Interfaces:

- CLI: `nexora evidence provenance [--capability-id 85] [--limit 500]`
- Web dashboard: `/api/evidence-provenance` and optional `?capability_id=85`
- Terminal dashboard: option 6, Evidence provenance

NEXORA does not fetch the source, resolve the revision, compare remote content, prove authorship, or detect upstream changes in this version. A URI and revision are operator assertions bound into the append-only ledger hash. They are not independent source verification. Legacy records remain unchanged and report `UNDECLARED`.
