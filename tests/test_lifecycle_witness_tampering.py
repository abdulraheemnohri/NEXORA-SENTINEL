from __future__ import annotations

import base64
import json

import pytest

from nexora.backup import generate_backup_signing_key
from nexora.lifecycle_chain import verify_lifecycle_chain_anchor, verify_lifecycle_chain_file
from nexora.oversight.witness import IndependentWitness, WitnessVerificationError
from nexora.registry import CapabilityRegistry


def _anchored_registry(tmp_path):
    database = tmp_path / "registry.sqlite3"
    registry = CapabilityRegistry(database)
    registry.register(7, "Witness tamper test", "A", source_record=True)
    private_key = tmp_path / "witness-private.pem"
    public_key = tmp_path / "witness-public.pem"
    generate_backup_signing_key(private_key, public_key)
    witness_log = tmp_path / "independent" / "lifecycle.jsonl"
    chain = verify_lifecycle_chain_file(database)
    IndependentWitness(witness_log, private_key).attest(
        chain["head_hash"], "lifecycle_chain_head"
    )
    return database, witness_log, public_key


def test_modified_witness_signature_blocks_recovery_anchor(tmp_path):
    database, witness_log, public_key = _anchored_registry(tmp_path)
    receipt = json.loads(witness_log.read_text(encoding="utf-8"))
    signature = bytearray(base64.b64decode(receipt["signature"], validate=True))
    signature[0] ^= 0x01
    receipt["signature"] = base64.b64encode(signature).decode("ascii")
    witness_log.write_text(json.dumps(receipt) + "\\n", encoding="utf-8")

    with pytest.raises(WitnessVerificationError, match=r"receipt_signature_invalid:1"):
        verify_lifecycle_chain_anchor(database, witness_log, public_key)


def test_untrusted_witness_key_blocks_recovery_anchor(tmp_path):
    database, witness_log, _trusted_public_key = _anchored_registry(tmp_path)
    other_private = tmp_path / "other-private.pem"
    other_public = tmp_path / "other-public.pem"
    generate_backup_signing_key(other_private, other_public)

    with pytest.raises(WitnessVerificationError, match=r"receipt_signer_untrusted:1"):
        verify_lifecycle_chain_anchor(database, witness_log, other_public)


def test_malformed_trailing_witness_receipt_blocks_recovery_anchor(tmp_path):
    database, witness_log, public_key = _anchored_registry(tmp_path)
    with witness_log.open("a", encoding="utf-8") as stream:
        stream.write("not-json\\n")

    with pytest.raises(WitnessVerificationError, match=r"receipt_format_invalid:2"):
        verify_lifecycle_chain_anchor(database, witness_log, public_key)
