"""Validated local-first settings."""
from __future__ import annotations
import json
from dataclasses import asdict, dataclass
from pathlib import Path

@dataclass(frozen=True)
class Settings:
    data_dir: str = "data"
    autonomy_level: str = "L0"
    max_actions_per_hour: int = 30
    max_wall_seconds_per_job: int = 60
    scheduler_enabled: bool = False
    sandbox_enabled: bool = False
    network_enabled: bool = False

    def validate(self) -> "Settings":
        if self.autonomy_level not in {"L0", "L1"}:
            raise ValueError("autonomy_level_must_be_L0_or_L1")
        if type(self.max_actions_per_hour) is not int or not 1 <= self.max_actions_per_hour <= 1000:
            raise ValueError("max_actions_per_hour_out_of_range")
        if type(self.max_wall_seconds_per_job) is not int or not 1 <= self.max_wall_seconds_per_job <= 3600:
            raise ValueError("max_wall_seconds_per_job_out_of_range")
        if any(type(v) is not bool for v in (self.scheduler_enabled, self.sandbox_enabled, self.network_enabled)):
            raise ValueError("feature_flags_must_be_boolean")
        return self

    @classmethod
    def load(cls, path: Path) -> "Settings":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or set(raw) - set(asdict(cls()).keys()):
            raise ValueError("configuration_schema_invalid")
        return cls(**raw).validate()

    def save(self, path: Path) -> None:
        self.validate()
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(asdict(self), indent=2) + "\n", encoding="utf-8")
