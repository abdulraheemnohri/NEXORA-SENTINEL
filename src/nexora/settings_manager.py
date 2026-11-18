"""Safe, read-only settings inspection and validation."""
from __future__ import annotations

import json
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
    if not source.exists():
        return Settings().validate(), False
    if not source.is_file():
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
