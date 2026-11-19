"""Safe, read-only settings inspection and validation."""
from __future__ import annotations

import json
import stat
from dataclasses import asdict
from pathlib import Path
from typing import Any

from nexora.config import Settings


def load_settings(path: Path | None = None) -> tuple[Settings, bool]:
    """Load a validated settings file, or validated defaults when it is absent.

    Returns (settings, file_present). Invalid existing files raise; they are
    never silently replaced with defaults.
    """
    if path is None:
        return Settings().validate(), False
    source = Path(path)
    try:
        metadata = source.lstat()
    except FileNotFoundError:
        return Settings().validate(), False
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError("settings_path_is_symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("settings_path_not_a_file")
    return Settings.load(source), True


def settings_report(path: Path | None = None) -> dict[str, Any]:
    settings, present = load_settings(path)
    return {
        "valid": True,
        "source": str(path) if present and path is not None else "built-in defaults",
        "file_present": present,
        "settings": asdict(settings),
        "safety": {
            "autonomy_level": settings.autonomy_level,
            "execution_enabled": False,
            "policy_mutation_enabled": False,
            "note": "Settings inspection does not enable scheduler, sandbox, network, tools, or autonomy.",
        },
    }


def render_settings(path: Path | None = None) -> str:
    return json.dumps(settings_report(path), indent=2, sort_keys=True)


def settings_diff_report(current_path: Path | None, candidate_path: Path) -> dict[str, Any]:
    """Build a read-only change preview; never authorize or apply settings."""
    current, current_present = load_settings(current_path)
    candidate_source = Path(candidate_path)
    candidate, candidate_present = load_settings(candidate_source)
    if not candidate_present:
        raise ValueError("candidate_settings_file_required")

    before = asdict(current)
    after = asdict(candidate)
    changes = [
        {"setting": key, "current": before[key], "candidate": after[key]}
        for key in before
        if before[key] != after[key]
    ]
    changed = bool(changes)
    return {
        "valid": True,
        "current_source": str(current_path) if current_present else "built-in defaults",
        "candidate_source": str(candidate_source),
        "changed_count": len(changes),
        "changes": changes,
        "status": "REVIEW_REQUIRED" if changed else "NO_CHANGES",
        "authorization": "NOT_EVALUATED",
        "reason": "per_setting_authorization_policy_not_defined" if changed else "candidate_matches_current_settings",
        "human_review_required": changed,
        "apply_supported": False,
        "execution_enabled": False,
    }