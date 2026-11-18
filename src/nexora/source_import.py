"""Validate source-backed import candidates without mutating canonical specifications."""
from __future__ import annotations

import hashlib
import json
import sysconfig
from pathlib import Path
from typing import Any

from nexora.catalog import CATALOG, EXPECTED_FAMILIES, VALID_STATUSES
from nexora.source_status import META_RULES

CAPABILITY_FIELDS = {"id", "name", "family", "family_name", "status", "source"}
RULE_FIELDS = {"id", "title", "text", "status", "mutable_by_agent"}


class SourceImportError(ValueError):
    """Raised when a source-import candidate cannot be safely previewed."""


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceImportError(f"cannot_read_json:{path}") from exc
    if not isinstance(value, dict):
        raise SourceImportError("artifact_root_must_be_object")
    return value


def _default_rules_path() -> Path:
    package_spec = Path(sysconfig.get_path("data")) / "share" / "nexora" / "spec"
    packaged = package_spec / "meta_rules.json"
    return packaged if packaged.is_file() else META_RULES


def preview_source_import(
    artifact_path: Path,
    *,
    kind: str,
    source_ref: str,
    catalog_path: Path = CATALOG,
    rules_path: Path | None = None,
) -> dict[str, Any]:
    """Return a deterministic review preview; never writes canonical files."""
    if kind not in {"capability", "meta-rule"}:
        raise SourceImportError("kind_must_be_capability_or_meta-rule")
    if not isinstance(source_ref, str) or not source_ref.strip():
        raise SourceImportError("source_ref_required")

    artifact_path = Path(artifact_path)
    raw = artifact_path.read_bytes()
    try:
        candidate = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceImportError("artifact_must_be_valid_utf8_json") from exc
    if not isinstance(candidate, dict):
        raise SourceImportError("artifact_root_must_be_object")

    key = "capabilities" if kind == "capability" else "rules"
    rows = candidate.get(key)
    if not isinstance(rows, list) or not rows:
        raise SourceImportError(f"{key}_must_be_nonempty_list")

    if kind == "capability":
        existing_root = _load_object(Path(catalog_path))
        existing_rows = existing_root.get("capabilities", [])
        maximum = 264
        required = CAPABILITY_FIELDS
    else:
        existing_root = _load_object(Path(rules_path) if rules_path else _default_rules_path())
        existing_rows = existing_root.get("rules", [])
        maximum = 45
        required = RULE_FIELDS
    if not isinstance(existing_rows, list):
        raise SourceImportError("canonical_records_must_be_list")

    existing_ids: set[int] = set()
    for row in existing_rows:
        if isinstance(row, dict) and type(row.get("id")) is int:
            existing_ids.add(row["id"])

    seen: set[int] = set()
    normalized: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise SourceImportError(f"record_{index}_must_be_object")
        missing = sorted(required - row.keys())
        if missing:
            raise SourceImportError(f"record_{index}_missing_fields:{','.join(missing)}")
        identifier = row["id"]
        if type(identifier) is not int or not 1 <= identifier <= maximum:
            raise SourceImportError(f"record_{index}_invalid_id")
        if identifier in seen:
            raise SourceImportError(f"duplicate_candidate_id:{identifier}")
        if identifier in existing_ids:
            raise SourceImportError(f"existing_id_collision:{identifier}")
        seen.add(identifier)

        if kind == "capability":
            if any(not isinstance(row[field], str) or not row[field].strip()
                   for field in ("name", "family_name", "source")):
                raise SourceImportError(f"record_{identifier}_invalid_text_field")
            if row["family"] not in EXPECTED_FAMILIES | {"CROSS-CUTTING"}:
                raise SourceImportError(f"record_{identifier}_invalid_family")
            if row["status"] not in VALID_STATUSES:
                raise SourceImportError(f"record_{identifier}_invalid_status")
        else:
            if any(not isinstance(row[field], str) or not row[field].strip()
                   for field in ("title", "text", "status")):
                raise SourceImportError(f"record_{identifier}_invalid_text_field")
            if type(row["mutable_by_agent"]) is not bool:
                raise SourceImportError(f"record_{identifier}_mutable_flag_must_be_boolean")
        normalized.append(row)

    normalized.sort(key=lambda item: item["id"])
    return {
        "status": "PREVIEW_READY",
        "kind": kind,
        "source_ref": source_ref.strip(),
        "artifact": str(artifact_path),
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "candidate_count": len(normalized),
        "candidate_ids": [row["id"] for row in normalized],
        "records": normalized,
        "canonical_write_performed": False,
        "human_approval_recorded": False,
        "automatic_import_enabled": False,
        "execution_enabled": False,
        "policy_mutation_enabled": False,
        "next_step": "Review this preview against the original source, then submit an explicitly approved change through a separately audited process.",
    }
