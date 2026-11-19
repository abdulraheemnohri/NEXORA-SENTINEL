# Local evidence artifact integrity verification

The evidence ledger stores operator-supplied SHA-256 attestations. The
`evidence verify-artifact` command now hashes an actual local regular file and
compares its bytes with one exact, previously recorded ledger row.

```sh
nexora evidence verify-artifact 85 1 --path ./reports/test-report.json
nexora evidence verify-artifact 85 1 --path ./reports/test-report.json \
  --reference "git:commit/0123456789abcdef"
```

Arguments identify the capability, exact ledger sequence, and local path.
`--reference` optionally requires an exact match with the record's reference.
The ledger hash chain is verified before the file is opened. Symbolic links
and non-regular files are rejected. Files are streamed in 1 MiB chunks with a
2 GiB upper bound; no artifact is copied or modified.

A `MATCH` means only that the file bytes equal the digest in the selected
ledger row. It does not authenticate the author, validate the file's meaning,
establish safety, or approve a capability. A mismatch is a report, not a
ledger mutation. Verification never changes lifecycle, policy, or execution
permissions.

The check is local and subject to ordinary filesystem race limitations. For
high-assurance use, verify from a trusted, immutable artifact store and retain
externally witnessed ledger backups.
