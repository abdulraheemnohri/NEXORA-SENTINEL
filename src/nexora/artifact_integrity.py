"""Read-only verification of local files against ledger attestations.

A matching digest proves byte equality with the recorded digest only. It does
not prove authorship, safety, semantic correctness, or approval.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

from nexora.evidence import EvidenceLedger

CHUNK_SIZE = 1024 * 1024
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024


class ArtifactVerificationError(ValueError):
    """Raised when an artifact cannot be safely verified."""


def _reject_symlink_components(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise ArtifactVerificationError("artifact_path_unavailable") from exc
        if stat.S_ISLNK(mode):
            raise ArtifactVerificationError("symlink_component_not_allowed")
    return absolute


def verify_artifact_file(
    database: Path,
    capability_id: int,
    sequence: int,
    artifact_path: Path,
    *,
    expected_reference: str | None = None,
) -> dict[str, Any]:
    """Hash one regular local file and compare it with one verified ledger row."""
    if type(capability_id) is not int or not 1 <= capability_id <= 264:
        raise ArtifactVerificationError("capability_id_out_of_range")
    if type(sequence) is not int or sequence < 1:
        raise ArtifactVerificationError("evidence_sequence_out_of_range")
    if expected_reference is not None and (
        not isinstance(expected_reference, str) or not expected_reference.strip()
    ):
        raise ArtifactVerificationError("expected_reference_invalid")

    ledger = EvidenceLedger(Path(database), readonly=True)
    chain = ledger.verify()
    if not chain["valid"]:
        raise ArtifactVerificationError("evidence_ledger_integrity_failure")
    row = ledger.get_record(sequence, capability_id)
    if row is None:
        raise ArtifactVerificationError("evidence_record_not_found")
    if expected_reference is not None and row["reference"] != expected_reference:
        raise ArtifactVerificationError("evidence_reference_mismatch")

    path = _reject_symlink_components(Path(artifact_path))
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ArtifactVerificationError("artifact_open_failed") from exc
    digest = hashlib.sha256()
    total = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ArtifactVerificationError("artifact_must_be_regular_file")
        if metadata.st_size > MAX_ARTIFACT_BYTES:
            raise ArtifactVerificationError("artifact_exceeds_size_limit")
        while True:
            chunk = os.read(descriptor, CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ARTIFACT_BYTES:
                raise ArtifactVerificationError("artifact_exceeds_size_limit")
            digest.update(chunk)
    finally:
        os.close(descriptor)

    actual = digest.hexdigest()
    matches = actual == row["artifact_sha256"]
    return {
        "verified": matches,
        "status": "MATCH" if matches else "HASH_MISMATCH",
        "capability_id": capability_id,
        "evidence_sequence": sequence,
        "evidence_type": row["evidence_type"],
        "reference": row["reference"],
        "artifact_path": str(path),
        "expected_sha256": row["artifact_sha256"],
        "actual_sha256": actual,
        "bytes_hashed": total,
        "ledger_chain_valid": True,
        "authorization_granted": False,
        "lifecycle_changed": False,
        "execution_enabled": False,
        "interpretation": "Byte equality only; authenticity, safety, and semantic validity are not established.",
    }
