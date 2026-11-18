"""Recovery readiness scoring and fail-closed recovery settings."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexora.backup_inventory import build_backup_inventory
from nexora.recovery_planner import RecoveryPlanningError, build_recovery_plan


class RecoveryReadinessError(ValueError):
    """Raised when recovery readiness settings or inputs are unsafe."""


@dataclass(frozen=True)
class RecoverySettings:
    backup_directory: str = "data/backups"
    trusted_public_key: str = ""
    retention_days: int = 30
    keep_latest: int = 3
    max_backup_age_hours: int = 168
    min_verified_points: int = 1
    require_simulation_confirmation: bool = True
    automatic_restore: bool = False
    automatic_deletion: bool = False

    def validate(self) -> RecoverySettings:
        for name in ("retention_days", "keep_latest", "max_backup_age_hours", "min_verified_points"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise RecoveryReadinessError(f"{name}_must_be_positive_integer")
        if not isinstance(self.backup_directory, str) or not self.backup_directory.strip():
            raise RecoveryReadinessError("backup_directory_required")
        if not isinstance(self.trusted_public_key, str):
            raise RecoveryReadinessError("trusted_public_key_must_be_string")
        if type(self.require_simulation_confirmation) is not bool:
            raise RecoveryReadinessError("require_simulation_confirmation_must_be_boolean")
        if self.automatic_restore is not False or self.automatic_deletion is not False:
            raise RecoveryReadinessError("automatic_recovery_actions_are_prohibited")
        return self

    @classmethod
    def load(cls, path: Path) -> RecoverySettings:
        source = Path(path)
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RecoveryReadinessError("recovery_settings_unreadable") from exc
        if not isinstance(raw, dict) or set(raw) - set(asdict(cls()).keys()):
            raise RecoveryReadinessError("recovery_settings_schema_invalid")
        try:
            return cls(**raw).validate()
        except TypeError as exc:
            raise RecoveryReadinessError("recovery_settings_schema_invalid") from exc


def build_recovery_readiness(
    directory: Path,
    *,
    trusted_public_key: Path | None,
    retention_days: int = 30,
    keep_latest: int = 3,
    max_backup_age_hours: int = 168,
    min_verified_points: int = 1,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Score verified recovery readiness; never restore, delete, or mutate artifacts."""
    instant = now or datetime.now(UTC)
    if instant.tzinfo is None:
        raise RecoveryReadinessError("recovery_clock_must_be_timezone_aware")
    if max_backup_age_hours < 1 or min_verified_points < 1:
        raise RecoveryReadinessError("readiness_thresholds_must_be_positive")
    backup_directory = Path(directory)
    if backup_directory.is_symlink():
        raise RecoveryReadinessError("backup_inventory_directory_not_found_or_unsafe")
    if not backup_directory.is_dir():
        return {
            "status": "NO_BACKUP_DIRECTORY",
            "score": 0,
            "verified_recovery_points": 0,
            "inventory_counts": {},
            "issues": ["configured_backup_directory_does_not_exist"],
            "recovery_simulation": "NOT_RECORDED",
            "read_only": True,
            "automatic_restore": False,
            "automatic_deletion": False,
        }
    if trusted_public_key is None:
        inventory = build_backup_inventory(backup_directory, now=instant)
        return {
            "status": "BLOCKED_TRUST_ANCHOR",
            "score": 0,
            "verified_recovery_points": 0,
            "inventory_counts": inventory["counts"],
            "issues": ["independent_trusted_public_key_not_configured"],
            "recovery_simulation": "NOT_RECORDED",
            "read_only": True,
            "automatic_restore": False,
            "automatic_deletion": False,
        }
    try:
        plan = build_recovery_plan(
            directory, trusted_public_key=trusted_public_key,
            retention_days=retention_days, keep_latest=keep_latest, now=instant,
        )
    except (RecoveryPlanningError, OSError, ValueError) as exc:
        raise RecoveryReadinessError(str(exc)) from exc
    points = plan["recovery_points"]
    issues: list[str] = []
    score = 100
    newest_age_hours: float | None = None
    if not points:
        score = 0
        issues.append("no_cryptographically_verified_recovery_points")
    else:
        newest = points[0]
        point_time = datetime.fromisoformat(newest["recovery_point_time"])
        if point_time.tzinfo is None:
            point_time = point_time.replace(tzinfo=UTC)
        newest_age_hours = max(0.0, (instant - point_time).total_seconds() / 3600)
        if newest_age_hours > max_backup_age_hours:
            score -= 30
            issues.append("newest_verified_backup_exceeds_maximum_age")
        if len(points) < min_verified_points:
            score -= 30
            issues.append("verified_backup_count_below_minimum")
    if plan["unusable_artifacts"]:
        score -= min(20, 5 * len(plan["unusable_artifacts"]))
        issues.append("unusable_backup_artifacts_need_review")
    score = max(0, score)
    ready = bool(points) and len(points) >= min_verified_points and newest_age_hours is not None and newest_age_hours <= max_backup_age_hours
    status = "READY" if ready and score >= 85 else ("DEGRADED" if points else "NOT_READY")
    if not issues:
        issues.append("verified_backup_inventory_meets_configured_thresholds")
    return {
        "status": status,
        "score": score,
        "score_basis": "deterministic_inventory_and_freshness_rules",
        "verified_recovery_points": len(points),
        "minimum_verified_points": min_verified_points,
        "newest_backup_age_hours": round(newest_age_hours, 2) if newest_age_hours is not None else None,
        "maximum_backup_age_hours": max_backup_age_hours,
        "unusable_artifact_count": len(plan["unusable_artifacts"]),
        "retention_proposals": plan["retention"]["proposals"],
        "issues": issues,
        "recovery_simulation": "NOT_RECORDED",
        "read_only": True,
        "automatic_restore": False,
        "automatic_deletion": False,
        "live_database_replacement": False,
    }


__all__ = ["RecoveryReadinessError", "RecoverySettings", "build_recovery_readiness"]
