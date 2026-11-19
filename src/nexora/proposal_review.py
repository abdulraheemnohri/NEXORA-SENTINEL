"""Domain-separated Ed25519 proposal-review attestations.

Signed reviews are immutable review evidence only. They do not grant lifecycle
approval, authorize policy/settings changes, or enable proposal execution.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import sqlite3
import stat
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nexora.approval import ApprovalError, load_private_key, public_key_fingerprint

SCHEMA_VERSION = 1
DOMAIN = "NEXORA-SENTINEL:PROPOSAL-REVIEW:v1"
MAX_TTL_SECONDS = 900
CLOCK_SKEW_SECONDS = 60
MIN_REVIEWERS = 2
MAX_REVIEWERS = 5
PROPOSAL_ID = re.compile(r"^[0-9a-f]{24}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{24,128}$")
DECISIONS = {"REVIEWED", "REJECTED"}
RECEIPT_FIELDS = {
    "schema_version", "domain", "proposal_id", "proposal_sha256",
    "decision", "evidence", "evidence_sha256", "approver_id",
    "issued_at", "expires_at", "nonce", "key_fingerprint",
}


class ProposalReviewError(ValueError):
    """Raised when a proposal-review receipt or stored attestation is invalid."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _evidence(evidence: Any) -> list[str]:
    if isinstance(evidence, str) or not isinstance(evidence, (list, tuple)):
        raise ProposalReviewError("proposal_review_evidence_must_be_a_collection")
    if not 1 <= len(evidence) <= 100:
        raise ProposalReviewError("proposal_review_evidence_count_invalid")
    values = []
    for item in evidence:
        if not isinstance(item, str) or not item.strip() or len(item) > 512:
            raise ProposalReviewError("proposal_review_evidence_invalid")
        values.append(item.strip())
    if len(set(values)) != len(values):
        raise ProposalReviewError("proposal_review_evidence_duplicate")
    return sorted(values)


def _evidence_hash(items: list[str]) -> str:
    return hashlib.sha256(_canonical({"evidence": items})).hexdigest()


def _regular_file(path: Path, label: str) -> Path:
    source = Path(path)
    try:
        info = source.lstat()
    except FileNotFoundError as exc:
        raise ProposalReviewError(f"{label}_not_found") from exc
    except OSError as exc:
        raise ProposalReviewError(f"{label}_unreadable") from exc
    if stat.S_ISLNK(info.st_mode):
        raise ProposalReviewError(f"{label}_symlink_refused")
    if not stat.S_ISREG(info.st_mode):
        raise ProposalReviewError(f"{label}_not_a_regular_file")
    return source


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProposalReviewError("proposal_review_duplicate_json_key")
        result[key] = value
    return result


def read_receipt_file(path: Path) -> dict[str, Any]:
    source = _regular_file(Path(path), "proposal_review_receipt")
    try:
        if source.stat().st_size > 128_000:
            raise ProposalReviewError("proposal_review_receipt_too_large")
        data = json.loads(
            source.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except ProposalReviewError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProposalReviewError("proposal_review_receipt_unreadable") from exc
    if not isinstance(data, dict):
        raise ProposalReviewError("proposal_review_receipt_schema_invalid")
    return data


def _proposal_record(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    try:
        evidence = json.loads(row["evidence_json"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ProposalReviewError("proposal_evidence_json_invalid") from exc
    if (
        not isinstance(evidence, list)
        or any(not isinstance(item, str) or not item.strip() for item in evidence)
    ):
        raise ProposalReviewError("proposal_evidence_schema_invalid")
    proposal = {
        "proposal_id": row["proposal_id"],
        "family": row["family"],
        "summary": row["summary"],
        "evidence": evidence,
        "payload_sha256": row["payload_sha256"],
        "execution": row["execution"],
    }
    if proposal["execution"] != "DISABLED":
        raise ProposalReviewError("proposal_execution_invariant_broken")
    if (
        not isinstance(proposal["proposal_id"], str)
        or not PROPOSAL_ID.fullmatch(proposal["proposal_id"])
    ):
        raise ProposalReviewError("proposal_id_invalid")
    if (
        not isinstance(proposal["payload_sha256"], str)
        or not SHA256.fullmatch(proposal["payload_sha256"])
    ):
        raise ProposalReviewError("proposal_digest_schema_invalid")
    return proposal


def _proposal_hash(proposal: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(proposal)).hexdigest()


def _load_proposal(database: Path, proposal_id: str) -> dict[str, Any]:
    if not isinstance(proposal_id, str) or not PROPOSAL_ID.fullmatch(proposal_id):
        raise ProposalReviewError("proposal_id_invalid")
    source = _regular_file(Path(database), "proposal_database")
    try:
        connection = sqlite3.connect(
            source.resolve().as_uri() + "?mode=ro", uri=True, timeout=5
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        try:
            row = connection.execute(
                "SELECT proposal_id,family,summary,evidence_json,payload_sha256,execution "
                "FROM self_family_proposals WHERE proposal_id=?",
                (proposal_id,),
            ).fetchone()
            if row is None:
                raise ProposalReviewError("unknown_proposal")
            return _proposal_record(row)
        finally:
            connection.close()
    except ProposalReviewError:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise ProposalReviewError("proposal_database_read_failed") from exc


def create_proposal_review_receipt(
    database: Path,
    proposal_id: str,
    private_key_path: Path,
    *,
    decision: str,
    evidence: list[str] | tuple[str, ...],
    approver_id: str,
    ttl_seconds: int = MAX_TTL_SECONDS,
    now: int | None = None,
) -> dict[str, Any]:
    """Create a signed review attestation without modifying the proposal database."""
    if decision not in DECISIONS:
        raise ProposalReviewError("proposal_review_decision_invalid")
    if (
        not isinstance(approver_id, str)
        or not approver_id.strip()
        or len(approver_id) > 256
    ):
        raise ProposalReviewError("proposal_review_approver_id_invalid")
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise ProposalReviewError("proposal_review_ttl_out_of_range")
    issued = int(time.time()) if now is None else now
    if type(issued) is not int or issued < 0:
        raise ProposalReviewError("proposal_review_time_invalid")
    key_path = _regular_file(Path(private_key_path), "proposal_review_private_key")
    try:
        private_key = load_private_key(key_path)
    except (ApprovalError, OSError, ValueError) as exc:
        raise ProposalReviewError(str(exc)) from exc

    proposal = _load_proposal(Path(database), proposal_id)
    evidence_values = _evidence(evidence)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "domain": DOMAIN,
        "proposal_id": proposal_id,
        "proposal_sha256": _proposal_hash(proposal),
        "decision": decision,
        "evidence": evidence_values,
        "evidence_sha256": _evidence_hash(evidence_values),
        "approver_id": approver_id.strip(),
        "issued_at": issued,
        "expires_at": issued + ttl_seconds,
        "nonce": secrets.token_urlsafe(24),
        "key_fingerprint": public_key_fingerprint(private_key.public_key()),
    }
    signature = private_key.sign(_canonical(payload))
    return {
        "payload": payload,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def _decode_receipt(receipt: Any) -> tuple[dict[str, Any], bytes]:
    if not isinstance(receipt, dict) or set(receipt) != {"payload", "signature"}:
        raise ProposalReviewError("proposal_review_receipt_schema_invalid")
    payload = receipt["payload"]
    if not isinstance(payload, dict) or set(payload) != RECEIPT_FIELDS:
        raise ProposalReviewError("proposal_review_payload_schema_invalid")
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != SCHEMA_VERSION
    ):
        raise ProposalReviewError("proposal_review_schema_version_unsupported")
    if payload["domain"] != DOMAIN:
        raise ProposalReviewError("proposal_review_domain_mismatch")
    if not isinstance(receipt["signature"], str):
        raise ProposalReviewError("proposal_review_signature_invalid")
    try:
        signature = base64.b64decode(receipt["signature"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ProposalReviewError("proposal_review_signature_invalid") from exc
    if len(signature) != 64:
        raise ProposalReviewError("proposal_review_signature_invalid")
    return payload, signature


def _verify_receipt(
    receipt: Any,
    *,
    proposal_id: str,
    proposal_sha256: str,
    verification_time: int,
    key_row: sqlite3.Row,
    historical: bool,
) -> dict[str, Any]:
    payload, signature = _decode_receipt(receipt)
    if (
        payload["proposal_id"] != proposal_id
        or payload["proposal_sha256"] != proposal_sha256
    ):
        raise ProposalReviewError("proposal_review_scope_mismatch")
    if payload["decision"] not in DECISIONS:
        raise ProposalReviewError("proposal_review_decision_invalid")
    evidence_values = _evidence(payload["evidence"])
    if evidence_values != payload["evidence"]:
        raise ProposalReviewError("proposal_review_evidence_not_canonical")
    if payload["evidence_sha256"] != _evidence_hash(evidence_values):
        raise ProposalReviewError("proposal_review_evidence_digest_mismatch")
    approver_id = payload["approver_id"]
    if (
        not isinstance(approver_id, str)
        or not approver_id.strip()
        or len(approver_id) > 256
    ):
        raise ProposalReviewError("proposal_review_approver_id_invalid")

    issued, expires = payload["issued_at"], payload["expires_at"]
    if (
        type(issued) is not int
        or type(expires) is not int
        or issued < 0
        or expires <= issued
        or expires - issued > MAX_TTL_SECONDS
        or issued > verification_time + CLOCK_SKEW_SECONDS
        or expires <= verification_time
    ):
        raise ProposalReviewError("proposal_review_receipt_outside_validity")

    nonce = payload["nonce"]
    if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
        raise ProposalReviewError("proposal_review_nonce_invalid")
    fingerprint = payload["key_fingerprint"]
    if not isinstance(fingerprint, str) or not SHA256.fullmatch(fingerprint):
        raise ProposalReviewError("proposal_review_fingerprint_invalid")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(key_row["public_key"])
    except (ValueError, TypeError) as exc:
        raise ProposalReviewError("proposal_review_trusted_key_invalid") from exc
    if public_key_fingerprint(public_key) != fingerprint:
        raise ProposalReviewError("proposal_review_trusted_key_fingerprint_mismatch")

    enrolled_at = key_row["enrolled_at"]
    key_expires = key_row["expires_at"]
    revoked_at = key_row["revoked_at"]
    active = key_row["active"]
    if (
        type(enrolled_at) is not int
        or type(key_expires) is not int
        or enrolled_at > issued
        or key_expires <= verification_time
        or key_expires <= issued
    ):
        raise ProposalReviewError("proposal_review_signing_key_not_valid_at_record_time")
    if historical:
        if revoked_at is not None:
            if type(revoked_at) is not int or revoked_at <= verification_time:
                raise ProposalReviewError("proposal_review_key_revoked_at_record_time")
        elif active != 1:
            raise ProposalReviewError("proposal_review_trust_metadata_inconsistent")
    elif active != 1 or revoked_at is not None:
        raise ProposalReviewError("proposal_review_signing_key_untrusted_or_revoked")
    try:
        public_key.verify(signature, _canonical(payload))
    except Exception as exc:
        raise ProposalReviewError("proposal_review_signature_invalid") from exc
    return payload


def _ensure_schema(connection: sqlite3.Connection) -> None:
    """Create the review tables inside the caller's active transaction."""
    statements = (
        """
        CREATE TABLE IF NOT EXISTS self_family_signed_reviews (
            proposal_id TEXT PRIMARY KEY REFERENCES self_family_proposals(proposal_id),
            decision TEXT NOT NULL CHECK(decision IN ('REVIEWED','REJECTED')),
            proposal_sha256 TEXT NOT NULL
                CHECK(length(proposal_sha256)=64 AND proposal_sha256 NOT GLOB '*[^0-9a-f]*'),
            evidence_json TEXT NOT NULL,
            evidence_sha256 TEXT NOT NULL
                CHECK(length(evidence_sha256)=64 AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'),
            approver_ids_json TEXT NOT NULL,
            signer_fingerprints_json TEXT NOT NULL,
            receipts_json TEXT NOT NULL,
            verified_at INTEGER NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS self_family_signed_review_nonces (
            nonce TEXT PRIMARY KEY,
            proposal_id TEXT NOT NULL REFERENCES self_family_proposals(proposal_id),
            fingerprint TEXT NOT NULL,
            consumed_at INTEGER NOT NULL
        )
        """,
        """
        CREATE TRIGGER IF NOT EXISTS self_family_signed_reviews_no_update
        BEFORE UPDATE ON self_family_signed_reviews BEGIN
            SELECT RAISE(ABORT, 'signed proposal reviews are append-only');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS self_family_signed_reviews_no_delete
        BEFORE DELETE ON self_family_signed_reviews BEGIN
            SELECT RAISE(ABORT, 'signed proposal reviews are append-only');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS self_family_signed_review_nonces_no_update
        BEFORE UPDATE ON self_family_signed_review_nonces BEGIN
            SELECT RAISE(ABORT, 'signed proposal review nonces are append-only');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS self_family_signed_review_nonces_no_delete
        BEFORE DELETE ON self_family_signed_review_nonces BEGIN
            SELECT RAISE(ABORT, 'signed proposal review nonces are append-only');
        END
        """,
    )
    for statement in statements:
        connection.execute(statement)


def record_signed_proposal_review(
    database: Path,
    proposal_id: str,
    receipts: list[dict[str, Any]],
    *,
    now: int | None = None,
    minimum_approvals: int = MIN_REVIEWERS,
    maximum_approvals: int = MAX_REVIEWERS,
) -> dict[str, Any]:
    """Verify 2–5 distinct enrolled signers and atomically append one review."""
    if not isinstance(receipts, list):
        raise ProposalReviewError("proposal_review_receipts_must_be_a_list")
    if (
        type(minimum_approvals) is not int
        or type(maximum_approvals) is not int
        or not 2 <= minimum_approvals <= maximum_approvals <= 5
    ):
        raise ProposalReviewError("proposal_review_threshold_invalid")
    if not minimum_approvals <= len(receipts) <= maximum_approvals:
        raise ProposalReviewError("proposal_review_threshold_not_met")
    if not isinstance(proposal_id, str) or not PROPOSAL_ID.fullmatch(proposal_id):
        raise ProposalReviewError("proposal_id_invalid")
    current = int(time.time()) if now is None else now
    if type(current) is not int or current < 0:
        raise ProposalReviewError("proposal_review_time_invalid")

    source = _regular_file(Path(database), "proposal_database")
    try:
        connection = sqlite3.connect(source, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise ProposalReviewError("proposal_database_write_open_failed") from exc

    try:
        connection.execute("BEGIN IMMEDIATE")
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if not {"self_family_proposals", "trusted_signing_keys"}.issubset(tables):
            raise ProposalReviewError("proposal_review_trust_or_proposal_store_unavailable")
        proposal_row = connection.execute(
            "SELECT proposal_id,family,summary,evidence_json,payload_sha256,execution "
            "FROM self_family_proposals WHERE proposal_id=?",
            (proposal_id,),
        ).fetchone()
        if proposal_row is None:
            raise ProposalReviewError("unknown_proposal")
        proposal = _proposal_record(proposal_row)
        proposal_sha = _proposal_hash(proposal)

        latest_event = connection.execute(
            "SELECT decision FROM self_family_review_events "
            "WHERE proposal_id=? ORDER BY event_id DESC LIMIT 1",
            (proposal_id,),
        ).fetchone()
        if latest_event is None or latest_event["decision"] != "SUBMITTED":
            raise ProposalReviewError("proposal_requires_pending_unsigned_review")

        _ensure_schema(connection)
        existing = connection.execute(
            "SELECT proposal_id FROM self_family_signed_reviews WHERE proposal_id=?",
            (proposal_id,),
        ).fetchone()
        if existing is not None:
            raise ProposalReviewError("proposal_signed_review_already_recorded")
        trust_columns = {
            row["name"] for row in connection.execute(
                "PRAGMA table_info(trusted_signing_keys)"
            )
        }
        required = {
            "fingerprint", "public_key", "active", "enrolled_at",
            "expires_at", "revoked_at",
        }
        if not required.issubset(trust_columns):
            raise ProposalReviewError("proposal_review_trust_store_schema_invalid")

        payloads = []
        approvers: set[str] = set()
        fingerprints: set[str] = set()
        nonces: set[str] = set()
        common_decision = None
        common_evidence = None
        for receipt in receipts:
            payload, _ = _decode_receipt(receipt)
            fingerprint = payload.get("key_fingerprint")
            if not isinstance(fingerprint, str) or not SHA256.fullmatch(fingerprint):
                raise ProposalReviewError("proposal_review_fingerprint_invalid")
            key_row = connection.execute(
                "SELECT public_key,active,enrolled_at,expires_at,revoked_at "
                "FROM trusted_signing_keys WHERE fingerprint=?",
                (fingerprint,),
            ).fetchone()
            if key_row is None:
                raise ProposalReviewError("proposal_review_signing_key_untrusted")
            verified = _verify_receipt(
                receipt,
                proposal_id=proposal_id,
                proposal_sha256=proposal_sha,
                verification_time=current,
                key_row=key_row,
                historical=False,
            )
            approver_id = verified["approver_id"]
            if fingerprint in fingerprints:
                raise ProposalReviewError("independent_proposal_review_keys_required")
            if approver_id in approvers:
                raise ProposalReviewError("distinct_proposal_review_approvers_required")
            if verified["nonce"] in nonces:
                raise ProposalReviewError("proposal_review_duplicate_nonce")
            if common_decision is None:
                common_decision = verified["decision"]
                common_evidence = verified["evidence"]
            elif (
                verified["decision"] != common_decision
                or verified["evidence"] != common_evidence
            ):
                raise ProposalReviewError("proposal_review_attestations_disagree")
            used = connection.execute(
                "SELECT 1 FROM self_family_signed_review_nonces WHERE nonce=?",
                (verified["nonce"],),
            ).fetchone()
            if used is not None:
                raise ProposalReviewError("proposal_review_replay_denied")
            approvers.add(approver_id)
            fingerprints.add(fingerprint)
            nonces.add(verified["nonce"])
            payloads.append(verified)

        if common_decision is None or common_evidence is None:
            raise ProposalReviewError("proposal_review_threshold_not_met")
        connection.execute(
            """
            INSERT INTO self_family_signed_reviews (
                proposal_id,decision,proposal_sha256,evidence_json,evidence_sha256,
                approver_ids_json,signer_fingerprints_json,receipts_json,verified_at
            ) VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (
                proposal_id,
                common_decision,
                proposal_sha,
                json.dumps(common_evidence, ensure_ascii=False, separators=(",", ":")),
                _evidence_hash(common_evidence),
                json.dumps([item["approver_id"] for item in payloads], separators=(",", ":")),
                json.dumps([item["key_fingerprint"] for item in payloads], separators=(",", ":")),
                json.dumps(receipts, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                current,
            ),
        )
        for payload in payloads:
            connection.execute(
                """
                INSERT INTO self_family_signed_review_nonces
                    (nonce,proposal_id,fingerprint,consumed_at)
                VALUES(?,?,?,?)
                """,
                (payload["nonce"], proposal_id, payload["key_fingerprint"], current),
            )
        connection.commit()
        return {
            "status": "VERIFIED_AND_RECORDED",
            "proposal_id": proposal_id,
            "decision": common_decision,
            "approver_ids": [item["approver_id"] for item in payloads],
            "signer_fingerprints": [item["key_fingerprint"] for item in payloads],
            "verified_at": current,
            "review_attestation_recorded": True,
            "lifecycle_approval_granted": False,
            "authorization": "NOT_GRANTED",
            "execution_enabled": False,
            "settings_mutation_enabled": False,
            "policy_mutation_enabled": False,
        }
    except ProposalReviewError:
        if connection.in_transaction:
            connection.rollback()
        raise
    except (sqlite3.Error, OSError, ValueError, TypeError) as exc:
        if connection.in_transaction:
            connection.rollback()
        raise ProposalReviewError("proposal_review_record_failed") from exc
    finally:
        connection.close()


def read_signed_proposal_review(
    connection: sqlite3.Connection,
    proposal_row: sqlite3.Row | dict[str, Any],
) -> dict[str, Any] | None:
    """Re-verify stored signatures and nonce consumption using pinned public keys."""
    tables = {
        row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    signed_tables = {
        "self_family_signed_reviews",
        "self_family_signed_review_nonces",
    }
    present_signed_tables = signed_tables.intersection(tables)
    if not present_signed_tables:
        return None
    if (
        present_signed_tables != signed_tables
        or "trusted_signing_keys" not in tables
    ):
        raise ProposalReviewError("proposal_review_verification_store_incomplete")
    proposal = _proposal_record(proposal_row)
    proposal_id = proposal["proposal_id"]
    proposal_sha = _proposal_hash(proposal)
    row = connection.execute(
        "SELECT * FROM self_family_signed_reviews WHERE proposal_id=?",
        (proposal_id,),
    ).fetchone()
    if row is None:
        orphan_nonces = connection.execute(
            "SELECT COUNT(*) FROM self_family_signed_review_nonces WHERE proposal_id=?",
            (proposal_id,),
        ).fetchone()[0]
        if orphan_nonces:
            raise ProposalReviewError("proposal_review_orphan_nonce_ledger")
        return None

    try:
        verified_at = row["verified_at"]
        if type(verified_at) is not int or verified_at < 0:
            raise ProposalReviewError("proposal_review_record_time_invalid")
        if row["proposal_sha256"] != proposal_sha:
            raise ProposalReviewError("proposal_review_stored_proposal_digest_mismatch")
        if row["decision"] not in DECISIONS:
            raise ProposalReviewError("proposal_review_stored_decision_invalid")
        evidence = _evidence(json.loads(row["evidence_json"]))
        if row["evidence_sha256"] != _evidence_hash(evidence):
            raise ProposalReviewError("proposal_review_stored_evidence_digest_mismatch")
        receipts = json.loads(row["receipts_json"])
        approvers = json.loads(row["approver_ids_json"])
        fingerprints = json.loads(row["signer_fingerprints_json"])
        if (
            not isinstance(receipts, list)
            or not MIN_REVIEWERS <= len(receipts) <= MAX_REVIEWERS
            or not isinstance(approvers, list)
            or not isinstance(fingerprints, list)
            or len(approvers) != len(receipts)
            or len(fingerprints) != len(receipts)
        ):
            raise ProposalReviewError("proposal_review_stored_quorum_invalid")

        used_nonces: set[str] = set()
        for index, receipt in enumerate(receipts):
            payload, _ = _decode_receipt(receipt)
            fingerprint = payload.get("key_fingerprint")
            if not isinstance(fingerprint, str) or not SHA256.fullmatch(fingerprint):
                raise ProposalReviewError("proposal_review_fingerprint_invalid")
            key_row = connection.execute(
                "SELECT public_key,active,enrolled_at,expires_at,revoked_at "
                "FROM trusted_signing_keys WHERE fingerprint=?",
                (fingerprint,),
            ).fetchone()
            if key_row is None:
                raise ProposalReviewError("proposal_review_signing_key_unknown")
            verified = _verify_receipt(
                receipt,
                proposal_id=proposal_id,
                proposal_sha256=proposal_sha,
                verification_time=verified_at,
                key_row=key_row,
                historical=True,
            )
            if (
                verified["decision"] != row["decision"]
                or verified["evidence"] != evidence
                or verified["approver_id"] != approvers[index]
                or verified["key_fingerprint"] != fingerprints[index]
            ):
                raise ProposalReviewError("proposal_review_stored_attestation_mismatch")
            if verified["nonce"] in used_nonces:
                raise ProposalReviewError("proposal_review_duplicate_nonce")
            nonce_row = connection.execute(
                "SELECT proposal_id,fingerprint,consumed_at "
                "FROM self_family_signed_review_nonces WHERE nonce=?",
                (verified["nonce"],),
            ).fetchone()
            if (
                nonce_row is None
                or nonce_row["proposal_id"] != proposal_id
                or nonce_row["fingerprint"] != fingerprint
                or nonce_row["consumed_at"] != verified_at
            ):
                raise ProposalReviewError("proposal_review_nonce_ledger_mismatch")
            used_nonces.add(verified["nonce"])

        nonce_count = connection.execute(
            "SELECT COUNT(*) FROM self_family_signed_review_nonces WHERE proposal_id=?",
            (proposal_id,),
        ).fetchone()[0]
        if nonce_count != len(receipts):
            raise ProposalReviewError("proposal_review_nonce_ledger_count_mismatch")
        if len(set(approvers)) != len(approvers):
            raise ProposalReviewError("proposal_review_duplicate_approver")
        if len(set(fingerprints)) != len(fingerprints):
            raise ProposalReviewError("proposal_review_duplicate_signer")
        return {
            "status": "VERIFIED",
            "decision": row["decision"],
            "proposal_sha256": proposal_sha,
            "evidence": evidence,
            "approver_ids": approvers,
            "signer_fingerprints": fingerprints,
            "verified_at": verified_at,
            "signer_count": len(receipts),
            "source_payload_digest": "RECORDED_NOT_RECOMPUTED",
            "lifecycle_approval_granted": False,
            "authorization": "NOT_GRANTED",
            "execution_enabled": False,
        }
    except ProposalReviewError:
        raise
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, sqlite3.Error) as exc:
        raise ProposalReviewError("proposal_review_stored_record_invalid") from exc
