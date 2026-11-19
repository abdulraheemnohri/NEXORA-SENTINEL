from __future__ import annotations

import shutil

from nexora.backup import create_backup, generate_backup_signing_key, restore_backup
from nexora.lifecycle_chain import verify_lifecycle_chain_anchor, verify_lifecycle_chain_file
from nexora.oversight.witness import IndependentWitness
from nexora.registry import CapabilityRegistry


def test_lifecycle_checkpoint_survives_signed_backup_restore_and_external_copy(tmp_path):
    """A copied trust bundle verifies a restored snapshot and detects later chain advance."""
    registry_path = tmp_path / "live" / "registry.sqlite3"
    registry = CapabilityRegistry(registry_path)
    registry.register(7, "Recovery qualification", "A", source_record=True)

    backup_private = tmp_path / "keys" / "backup-private.pem"
    backup_public = tmp_path / "keys" / "backup-public.pem"
    witness_private = tmp_path / "keys" / "witness-private.pem"
    witness_public = tmp_path / "keys" / "witness-public.pem"
    generate_backup_signing_key(backup_private, backup_public)
    generate_backup_signing_key(witness_private, witness_public)

    witness_log = tmp_path / "local-witness" / "lifecycle.jsonl"
    chain = verify_lifecycle_chain_file(registry_path)
    IndependentWitness(witness_log, witness_private).attest(
        chain["head_hash"], "lifecycle_chain_head"
    )

    backup_path = tmp_path / "transfer" / "registry.sqlite3"
    create_backup(registry_path, backup_path, signing_key=backup_private)
    restored_path = tmp_path / "restore-target" / "registry.sqlite3"
    restore_backup(backup_path, restored_path, trusted_public_key=backup_public)

    # This models transfer of witness material separately from the database backup.
    # It proves portability, not physical or administrative independence.
    external_trust = tmp_path / "external-trust"
    external_trust.mkdir()
    copied_witness_log = external_trust / "lifecycle.jsonl"
    copied_witness_public_key = external_trust / "witness-public.pem"
    shutil.copy2(witness_log, copied_witness_log)
    shutil.copy2(witness_public, copied_witness_public_key)

    anchored = verify_lifecycle_chain_anchor(
        restored_path, copied_witness_log, copied_witness_public_key
    )
    assert anchored["valid"] is True
    assert anchored["status"] == "ANCHORED"
    assert anchored["chain"]["head_hash"] == chain["head_hash"]

    restored_registry = CapabilityRegistry(restored_path)
    restored_registry.register(8, "Post-recovery event", "A", source_record=True)
    stale = verify_lifecycle_chain_anchor(
        restored_path, copied_witness_log, copied_witness_public_key
    )
    assert stale["valid"] is False
    assert stale["status"] == "ANCHOR_MISMATCH"
