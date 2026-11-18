"""Rollback decision record facade; no deployment mutation is performed."""
from nexora.registry import CapabilityRegistry


def record_rollback(registry: CapabilityRegistry, capability_id: int, from_release: str,
                    target_release: str, reason: str, evidence, *, approver_id: str):
    return registry.record_rollback(
        capability_id, from_release, target_release, reason, evidence, approver_id=approver_id
    )
