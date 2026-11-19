"""Strict, read-only model catalogue validation.

Catalogue entries are declarations, not trusted model files. A model without a
matching SHA-256 remains UNVERIFIED and no catalogue entry is executable.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from nexora.intelligence.provider_registry import builtin_registry

_DEFAULT_CONFIG = Path("config/models.yaml")
_MODEL_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}$")
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_TOP_LEVEL = {"version", "runtime_enabled", "network_downloads_enabled", "default_provider", "models"}
_MODEL_FIELDS = {"id", "provider", "artifact", "format", "modalities", "sha256"}
_ALLOWED_MODALITIES = {"text"}


class ModelCatalogError(ValueError):
    """Malformed or unsafe model catalogue."""


def _parse(path: Path) -> dict[str, Any]:
    source = Path(path)
    try:
        metadata = source.lstat()
    except FileNotFoundError:
        raise ModelCatalogError("model_catalog_missing") from None
    if source.is_symlink() or not source.is_file():
        raise ModelCatalogError("model_catalog_must_be_regular_file")
    try:
        value = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ModelCatalogError("model_catalog_unreadable_or_invalid") from exc
    if not isinstance(value, dict) or set(value) != _TOP_LEVEL:
        raise ModelCatalogError("model_catalog_schema_invalid")
    if type(value["version"]) is not int or value["version"] != 1:
        raise ModelCatalogError("model_catalog_version_unsupported")
    if type(value["runtime_enabled"]) is not bool:
        raise ModelCatalogError("model_catalog_runtime_flag_invalid")
    if type(value["network_downloads_enabled"]) is not bool:
        raise ModelCatalogError("model_catalog_network_flag_invalid")
    if value["default_provider"] is not None and not isinstance(value["default_provider"], str):
        raise ModelCatalogError("model_catalog_default_provider_invalid")
    if not isinstance(value["models"], list):
        raise ModelCatalogError("model_catalog_models_must_be_list")
    return value


def _artifact_path(root: Path, artifact: str) -> Path:
    if not isinstance(artifact, str) or not artifact or "\\" in artifact:
        raise ModelCatalogError("model_artifact_path_invalid")
    relative = PurePosixPath(artifact)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ModelCatalogError("model_artifact_path_must_be_relative_and_contained")
    base = Path(root).resolve()
    target = base.joinpath(*relative.parts)
    try:
        target.resolve().relative_to(base)
    except (OSError, ValueError) as exc:
        raise ModelCatalogError("model_artifact_path_escapes_model_root") from exc
    return target


def build_model_catalog_report(
    config_path: Path = _DEFAULT_CONFIG,
    *,
    model_dir: Path = Path("models"),
) -> dict[str, Any]:
    """Validate declarations and report file integrity without loading weights."""
    try:
        config = _parse(Path(config_path))
        registry = builtin_registry()
        if config["default_provider"] is not None:
            registry.get(config["default_provider"])
        records = []
        seen: set[str] = set()
        for item in config["models"]:
            if not isinstance(item, dict) or set(item) != _MODEL_FIELDS:
                raise ModelCatalogError("model_record_schema_invalid")
            model_id = item["id"]
            if not isinstance(model_id, str) or not _MODEL_ID.fullmatch(model_id):
                raise ModelCatalogError("model_id_invalid")
            if model_id in seen:
                raise ModelCatalogError("model_id_duplicate")
            seen.add(model_id)
            descriptor = registry.get(item["provider"])
            if item["format"] != "litertlm":
                raise ModelCatalogError("model_format_not_supported_by_provider")
            modalities = item["modalities"]
            if (
                not isinstance(modalities, list)
                or not modalities
                or any(not isinstance(value, str) or value not in descriptor.modalities for value in modalities)
                or len(set(modalities)) != len(modalities)
            ):
                raise ModelCatalogError("model_modalities_not_supported_by_provider")
            digest = item["sha256"]
            if digest is not None and (
                not isinstance(digest, str) or not _SHA256.fullmatch(digest)
            ):
                raise ModelCatalogError("model_sha256_invalid")
            target = _artifact_path(Path(model_dir), item["artifact"])
            if target.is_symlink():
                file_status = "SYMLINK_REJECTED"
                integrity = "UNVERIFIED"
            elif not target.is_file():
                file_status = "MISSING"
                integrity = "UNVERIFIED"
            elif digest is None:
                file_status = "PRESENT"
                integrity = "UNVERIFIED"
            else:
                hasher = hashlib.sha256()
                try:
                    with target.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            hasher.update(chunk)
                    integrity = "VERIFIED" if hasher.hexdigest().lower() == digest.lower() else "HASH_MISMATCH"
                    file_status = "PRESENT"
                except OSError:
                    file_status = "UNREADABLE"
                    integrity = "UNVERIFIED"
            records.append({
                "id": model_id,
                "provider": item["provider"],
                "artifact": item["artifact"],
                "format": item["format"],
                "modalities": modalities,
                "file_status": file_status,
                "integrity": integrity,
                "execution_eligible": False,
                "authorization": "NOT_GRANTED",
            })
        return {
            "status": "VALID" if records else "EMPTY",
            "valid": True,
            "count": len(records),
            "runtime_enabled_in_config": config["runtime_enabled"],
            "network_downloads_enabled_in_config": config["network_downloads_enabled"],
            "default_provider": config["default_provider"],
            "models": records,
            "model_loading": False,
            "execution_enabled": False,
            "note": "Catalogue validation and hash verification do not authorize model loading or inference.",
        }
    except (ModelCatalogError, OSError, ValueError) as exc:
        return {
            "status": "INVALID",
            "valid": False,
            "count": 0,
            "models": [],
            "error": str(exc),
            "model_loading": False,
            "execution_enabled": False,
        }
