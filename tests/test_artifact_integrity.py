from __future__ import annotations

import hashlib
import os

import pytest

from nexora.artifact_integrity import (
    ArtifactVerificationError,
    verify_artifact_file,
)
from nexora.evidence import EvidenceLedger


def test_verifies_real_file_against_exact_evidence_record(tmp_path):
    content = b"NEXORA evidence artifact\n"
    artifact = tmp_path / "artifact.txt"
    artifact.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    database = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(database)
    ledger.add(85, "test_report", "local:artifact.txt", digest, "operator")
    result = verify_artifact_file(
        database, 85, 1, artifact, expected_reference="local:artifact.txt",
    )
    assert result["verified"] is True
    assert result["status"] == "MATCH"
    assert result["bytes_hashed"] == len(content)
    assert result["authorization_granted"] is False
    assert result["execution_enabled"] is False


def test_reports_hash_mismatch_without_mutation(tmp_path):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("changed", encoding="utf-8")
    database = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(database)
    ledger.add(85, "test_report", "local:artifact.txt", "a" * 64, "operator")
    result = verify_artifact_file(database, 85, 1, artifact)
    assert result["verified"] is False
    assert result["status"] == "HASH_MISMATCH"
    assert ledger.verify()["valid"] is True


def test_refuses_symlink_artifact(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("data", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable on this platform")
    database = tmp_path / "registry.sqlite3"
    EvidenceLedger(database).add(
        85, "test_report", "local:link.txt",
        hashlib.sha256(b"data").hexdigest(), "operator",
    )
    with pytest.raises(ArtifactVerificationError, match="symlink_component"):
        verify_artifact_file(database, 85, 1, link)


def test_requires_exact_capability_and_sequence(tmp_path):
    artifact = tmp_path / "artifact.txt"
    artifact.write_bytes(b"x")
    database = tmp_path / "registry.sqlite3"
    EvidenceLedger(database).add(
        85, "test_report", "local:x", hashlib.sha256(b"x").hexdigest(), "operator",
    )
    with pytest.raises(ArtifactVerificationError, match="evidence_record_not_found"):
        verify_artifact_file(database, 86, 1, artifact)


def test_refuses_reference_mismatch(tmp_path):
    artifact = tmp_path / "artifact.txt"
    artifact.write_bytes(b"x")
    database = tmp_path / "registry.sqlite3"
    EvidenceLedger(database).add(
        85, "test_report", "source:expected",
        hashlib.sha256(b"x").hexdigest(), "operator",
    )
    with pytest.raises(ArtifactVerificationError, match="evidence_reference_mismatch"):
        verify_artifact_file(database, 85, 1, artifact, expected_reference="source:other")


def test_refuses_corrupt_ledger_before_hashing(tmp_path):
    import sqlite3

    artifact = tmp_path / "artifact.txt"
    artifact.write_bytes(b"x")
    database = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(database)
    ledger.add(85, "test_report", "local:x", hashlib.sha256(b"x").hexdigest(), "operator")
    with sqlite3.connect(database) as db:
        db.execute("DROP TRIGGER capability_evidence_no_update")
        db.execute("UPDATE capability_evidence SET note='tampered'")
    with pytest.raises(ArtifactVerificationError, match="ledger_integrity_failure"):
        verify_artifact_file(database, 85, 1, artifact)
