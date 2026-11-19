"""Validated local-first settings with JSON/YAML input support."""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Settings:
    data_dir: str = "data"
    autonomy_level: str = "L0"
    max_actions_per_hour: int = 30
    max_wall_seconds_per_job: int = 60
    scheduler_enabled: bool = False
    sandbox_enabled: bool = False
    network_enabled: bool = False

    def validate(self) -> Settings:
        if self.autonomy_level not in {"L0", "L1"}:
            raise ValueError("autonomy_level_must_be_L0_or_L1")
        if type(self.max_actions_per_hour) is not int or not 1 <= self.max_actions_per_hour <= 1000:
            raise ValueError("max_actions_per_hour_out_of_range")
        if type(self.max_wall_seconds_per_job) is not int or not 1 <= self.max_wall_seconds_per_job <= 3600:
            raise ValueError("max_wall_seconds_per_job_out_of_range")
        if any(type(v) is not bool for v in (self.scheduler_enabled, self.sandbox_enabled, self.network_enabled)):
            raise ValueError("feature_flags_must_be_boolean")
        if not isinstance(self.data_dir, str) or not self.data_dir.strip():
            raise ValueError("data_dir_required")
        return self

    @classmethod
    def load(cls, path: Path) -> Settings:
        source = Path(path)
        raw_text = source.read_text(encoding="utf-8")
        if source.suffix.lower() in {".yaml", ".yml"}:
            raw = yaml.safe_load(raw_text)
        else:
            raw = json.loads(raw_text)
        if not isinstance(raw, dict) or set(raw) - set(asdict(cls()).keys()):
            raise ValueError("configuration_schema_invalid")
        return cls(**raw).validate()

    def save(self, path: Path) -> None:
        """Atomically persist validated settings without following a target symlink.

        The temporary file is created beside the target, restricted to the
        current user, flushed before replacement, and removed on failure.
        This provides crash-safe file replacement, not authorization to change
        policy or enable any feature.
        """
        self.validate()
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            raise ValueError("settings_target_is_symlink")
        if target.exists() and not target.is_file():
            raise ValueError("settings_target_not_a_file")

        if target.suffix.lower() in {".yaml", ".yml"}:
            payload = yaml.safe_dump(asdict(self), sort_keys=True)
        else:
            payload = json.dumps(asdict(self), indent=2) + "\n"

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
        )
        temporary = Path(temporary_name)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                descriptor = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            if target.is_symlink():
                raise ValueError("settings_target_is_symlink")
            os.replace(temporary, target)
            if os.name == "posix":
                directory_fd = os.open(target.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
