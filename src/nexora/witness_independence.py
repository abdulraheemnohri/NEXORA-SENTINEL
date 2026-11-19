"""Read-only local witness key separation inspection."""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class WitnessIndependenceError(ValueError):
    """Raised when key material cannot be safely inspected."""


def _inspect_private_key(path: Path, role: str) -> dict[str, Any]:
    source = Path(path)
    try:
        metadata = source.lstat()
    except FileNotFoundError as exc:
        raise WitnessIndependenceError(f"{role}_key_missing") from exc
    except OSError as exc:
        raise WitnessIndependenceError(f"{role}_key_stat_failed") from exc

    if stat.S_ISLNK(metadata.st_mode):
        raise WitnessIndependenceError(f"{role}_key_symlink_refused")
    if not stat.S_ISREG(metadata.st_mode):
        raise WitnessIndependenceError(f"{role}_key_not_regular_file")

    permissions = "NOT_CHECKED"
    if os.name == "posix":
        permissions = (
            "RESTRICTED" if stat.S_IMODE(metadata.st_mode) & 0o077 == 0
            else "TOO_OPEN"
        )

    try:
        key = serialization.load_pem_private_key(source.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise WitnessIndependenceError(f"{role}_key_invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise WitnessIndependenceError(f"{role}_ed25519_private_key_required")

    public = key.public_key()
    raw = public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return {
        "role": role,
        "path": str(source),
        "resolved_path": str(source.resolve()),
        "parent_directory": str(source.resolve().parent),
        "fingerprint_sha256": hashlib.sha256(raw).hexdigest(),
        "private_key_permissions": permissions,
    }


def inspect_witness_independence(
    backup_private_key: Path,
    update_private_key: Path,
    witness_private_key: Path,
) -> dict[str, Any]:
    """Compare local key fingerprints and file locations without changing them.

    This can detect accidental key/path reuse and weak POSIX file modes. It
    cannot establish separate hosts, remote custody, hardware-backed storage,
    or a genuinely independent human/operator.
    """
    roles = [
        _inspect_private_key(backup_private_key, "backup"),
        _inspect_private_key(update_private_key, "update"),
        _inspect_private_key(witness_private_key, "witness"),
    ]

    fingerprints = [item["fingerprint_sha256"] for item in roles]
    resolved_paths = [item["resolved_path"] for item in roles]
    parent_directories = [item["parent_directory"] for item in roles]

    same_files = False
    for index, left in enumerate(
        (Path(item["path"]) for item in roles)
    ):
        for right in (Path(item["path"]) for item in roles[index + 1:]):
            try:
                if os.path.samefile(left, right):
                    same_files = True
            except OSError as exc:
                raise WitnessIndependenceError("key_file_identity_check_failed") from exc

    fingerprints_unique = len(set(fingerprints)) == len(fingerprints)
    paths_unique = len(set(resolved_paths)) == len(resolved_paths) and not same_files
    parent_directories_unique = len(set(parent_directories)) == len(parent_directories)
    permission_results = [item["private_key_permissions"] for item in roles]
    permissions_restricted = all(
        value == "RESTRICTED" for value in permission_results
    ) if os.name == "posix" else None

    local_separation = (
        fingerprints_unique
        and paths_unique
        and parent_directories_unique
        and permissions_restricted is not False
    )
    return {
        "status": "LOCAL_SEPARATION_CHECK_PASSED" if local_separation else "LOCAL_SEPARATION_NOT_ESTABLISHED",
        "keys": roles,
        "checks": {
            "fingerprints_unique": fingerprints_unique,
            "file_paths_unique": paths_unique,
            "parent_directories_unique": parent_directories_unique,
            "posix_private_permissions_restricted": permissions_restricted,
            "local_separation": local_separation,
        },
        "independence": {
            "same_host_separation": "NOT_ESTABLISHED",
            "off_device_custody": "NOT_VERIFIED",
            "remote_witness": "NOT_CONFIGURED",
            "hardware_backing": "NOT_VERIFIED",
            "independent_operator_identity": "NOT_VERIFIED",
        },
        "controls": {
            "read_only": True,
            "private_key_material_exposed": False,
            "key_files_modified": False,
            "execution_enabled": False,
            "policy_mutation_enabled": False,
        },
        "note": (
            "Distinct fingerprints, paths and parent directories establish only "
            "local file/key separation. They do not prove independent host custody, "
            "remote witnessing, hardware protection or independent human control."
        ),
    }
