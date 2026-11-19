# Lifecycle witness recovery qualification

## Purpose

This runbook qualifies portability of a lifecycle-chain checkpoint across a signed SQLite backup and restore. It is a verification workflow only; it does not restore over a live database, rotate keys, enable capabilities, or authorize execution.

## Required trust separation

Keep these artifacts under separate administrative control:

1. Registry backup and its signed manifest.
2. Backup-signing trusted public key, provisioned independently.
3. Lifecycle witness receipt log.
4. Lifecycle witness trusted public key, provisioned independently.
5. Witness private key, retained offline or by the independent witness operator.

Copying files into different directories on one host is not independent trust. A same-device test proves format portability only, not resistance to a privileged host compromise, remote attestation, or actual off-device custody.

## Operator procedure

1. Stop registry writers or take a consistent online backup using the normal `nexora backup` command.
2. Verify the backup using the separately provisioned backup public key.
3. Run `nexora lifecycle-history` and confirm the local chain is valid.
4. Create a lifecycle checkpoint with the dedicated witness key and a witness log stored outside the registry's writable trust domain:

   ```bash
   nexora lifecycle-chain-attest \
     --witness-key /secure/witness/lifecycle-private.pem \
     --witness-log /independent-storage/lifecycle.jsonl \
     --confirm
   ```

5. Transfer the backup, witness log, and public-key pins using independently controlled channels. Never transfer a private signing key with the backup.
6. Restore the signed backup to a new, non-existing destination path.
7. Verify the restored database against the copied witness log and independently pinned witness public key:

   ```bash
   nexora lifecycle-chain-verify \
     --database /recovery/registry.sqlite3 \
     --witness-log /independent-storage/lifecycle.jsonl \
     --trusted-witness-key /trusted-keys/lifecycle-public.pem
   ```

8. Require `ANCHORED`. A valid local chain without a matching external checkpoint is not independently anchored.
9. If new lifecycle events are appended after the checkpoint, expect `ANCHOR_MISMATCH`; create a new checkpoint only after an operator reviews the new chain head.

## Automated regression coverage

`tests/test_lifecycle_chain_recovery.py` creates a registry, signs a lifecycle head with a dedicated witness key, creates and restores a separately signed backup, copies the witness receipt and public-key pin to a separate test location, and verifies that:

- The restored chain retains the exact witnessed head.
- The copied witness material verifies the restored database.
- Appending a later lifecycle event invalidates the old checkpoint.

The test uses separate temporary directories on one test host. It does not claim cross-device or cross-administrator verification. Physical off-device qualification remains an operator/device test.

## Failure handling

Treat missing keys, unreadable witness storage, invalid signatures, a damaged chain, or a stale checkpoint as blocked. Do not fall back to trusting the local database, regenerate a trust key automatically, or rewrite the witness log to make verification pass.
