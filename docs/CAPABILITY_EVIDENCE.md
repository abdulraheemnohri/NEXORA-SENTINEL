# Capability evidence ledger

The evidence ledger records a human-supplied reference and SHA-256 digest for
artifacts associated with a capability. It is an audit aid, not proof that the
artifact is truthful, safe, complete, or even reachable.

## Commands

Initialize the registry first if desired:

```sh
nexora registry-init
```

Record a reference only after independently calculating the artifact digest:

```sh
nexora evidence add 85 \
  --type implementation_reference \
  --reference "git:commit/0123456789abcdef" \
  --sha256 <64-character-lowercase-sha256> \
  --operator "your-operator-id" \
  --note "Implementation review artifact" \
  --confirm
```

Inspect and verify:

```sh
nexora evidence list --capability-id 85
nexora evidence verify
```

Supported evidence types are the exact evidence tokens already declared by
`nexora.lifecycle.EVIDENCE_FOR`. No arbitrary evidence type is accepted.

## Integrity and limits

- Records are appended to `registry.sqlite3` in a separate table.
- SQLite triggers reject ordinary UPDATE and DELETE operations.
- Every record hashes its canonical fields and previous record hash.
- New schema-v2 records also bind their sequence number and UTC creation timestamp into the hash.
- Existing schema-v1 rows are retained and remain verifiable; the ledger adds a schema-version column without rewriting their historical hashes.
- Verification detects altered rows, broken links, and record-hash mismatches.
- The SHA-256 value is supplied by the operator; NEXORA does not fetch or hash
  the referenced artifact. Verify the artifact independently.
- The ledger does not establish the identity of the operator or the authenticity
  of the referenced artifact.
- A privileged actor able to rewrite the database and its schema can rewrite
  the local chain. Export and externally sign or witness backups for stronger
  tamper evidence.
- Evidence entries do not automatically satisfy lifecycle transitions, approve
  capabilities, change policy, or enable execution.
- No capability implementation is invoked by these commands.

Treat the ledger as provenance metadata, not a security boundary.


## Evidence readiness evaluation

Generate a read-only gate report for one capability:

```sh
nexora evidence evaluate 85
# Dashboard API: GET /api/evidence-evaluation?capability_id=85
```

The report compares the capability's complete set of recorded evidence tokens with the exact
requirements in `nexora.lifecycle.EVIDENCE_FOR`. The evaluator uses a full-ledger summary after
integrity verification; it is not limited by the 500-record display limit used by `evidence list`. It reports the first gate
that remains blocked, missing tokens, ledger integrity, and the evidence types
present. A corrupt ledger blocks every gate.

This is an evidence-presence assessment only. It does not inspect referenced
artifacts, verify operator identity, accept a human approval assertion, change
a capability's lifecycle state, or enable execution. In particular,
`human_approval` evidence is not itself proof of an authorized approver; the
approval gate remains blocked until a separate trusted authorization mechanism
is implemented. No lifecycle promotion is performed by this command.
