"""Provisional self-* capability domains with proposal-only behavior.

These operational domains are not substitutes for the canonical A–AN source
families. They provide safe interfaces while source-backed family definitions
are incomplete. Nothing in this module executes tools, modifies policy, writes
project files, or promotes its own proposals.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from collections.abc import Mapping


class SelfFamily(StrEnum):
    OBSERVATION = "self_observation"
    DIAGNOSTICS = "self_diagnostics"
    REPAIR_PLANNING = "self_repair_planning"
    LEARNING = "self_learning"
    GOVERNANCE_ASSISTANCE = "self_governance_assistance"
    EVOLUTION = "self_evolution"


@dataclass(frozen=True)
class SelfFamilyDefinition:
    family: SelfFamily
    purpose: str
    permitted_output: str
    may_mutate: bool = False
    may_execute: bool = False
    may_self_enable: bool = False


SELF_FAMILIES: tuple[SelfFamilyDefinition, ...] = (
    SelfFamilyDefinition(
        SelfFamily.OBSERVATION,
        "Collect bounded, read-only local state and runtime facts.",
        "timestamped diagnostic snapshot",
    ),
    SelfFamilyDefinition(
        SelfFamily.DIAGNOSTICS,
        "Classify observed faults and report evidence and uncertainty.",
        "diagnostic finding with source evidence",
    ),
    SelfFamilyDefinition(
        SelfFamily.REPAIR_PLANNING,
        "Draft reversible repair plans for independent human review.",
        "repair proposal with rollback and verification steps",
    ),
    SelfFamilyDefinition(
        SelfFamily.LEARNING,
        "Prepare provenance-linked knowledge candidates without changing trusted memory.",
        "untrusted knowledge candidate with source digest",
    ),
    SelfFamilyDefinition(
        SelfFamily.GOVERNANCE_ASSISTANCE,
        "Explain policy conflicts and missing approval evidence.",
        "governance analysis; policy kernel remains authoritative",
    ),
    SelfFamilyDefinition(
        SelfFamily.EVOLUTION,
        "Prepare staged change proposals for static checks, sandbox review and canary evaluation.",
        "versioned change proposal; promotion remains disabled",
    ),
)


@dataclass(frozen=True)
class SelfFamilySettings:
    observation_enabled: bool = True
    diagnostics_enabled: bool = True
    repair_planning_enabled: bool = False
    learning_enabled: bool = False
    governance_assistance_enabled: bool = False
    evolution_enabled: bool = False
    autonomy_level: str = "L0"

    def validate(self) -> SelfFamilySettings:
        flags = (
            self.observation_enabled,
            self.diagnostics_enabled,
            self.repair_planning_enabled,
            self.learning_enabled,
            self.governance_assistance_enabled,
            self.evolution_enabled,
        )
        if any(type(value) is not bool for value in flags):
            raise ValueError("self_family_flags_must_be_boolean")
        if self.autonomy_level not in {"L0", "L1"}:
            raise ValueError("self_family_autonomy_must_be_L0_or_L1")
        return self

    def enabled(self, family: SelfFamily) -> bool:
        self.validate()
        flag = {
            SelfFamily.OBSERVATION: self.observation_enabled,
            SelfFamily.DIAGNOSTICS: self.diagnostics_enabled,
            SelfFamily.REPAIR_PLANNING: self.repair_planning_enabled,
            SelfFamily.LEARNING: self.learning_enabled,
            SelfFamily.GOVERNANCE_ASSISTANCE: self.governance_assistance_enabled,
            SelfFamily.EVOLUTION: self.evolution_enabled,
        }[family]
        return flag


@dataclass(frozen=True)
class SelfFamilyProposal:
    proposal_id: str
    family: SelfFamily
    summary: str
    evidence: tuple[str, ...]
    payload_sha256: str
    status: str = "PENDING_HUMAN_REVIEW"
    execution: str = "DISABLED"

    def to_dict(self) -> dict:
        result = asdict(self)
        result["family"] = self.family.value
        return result


class SelfFamilyManager:
    """Build proposals only; execution and self-authorization are impossible here."""

    def __init__(self, settings: SelfFamilySettings | None = None):
        self.settings = (settings or SelfFamilySettings()).validate()
        self._definitions: Mapping[SelfFamily, SelfFamilyDefinition] = {
            item.family: item for item in SELF_FAMILIES
        }

    def catalogue(self) -> tuple[SelfFamilyDefinition, ...]:
        return SELF_FAMILIES

    def propose(
        self,
        family: SelfFamily,
        summary: str,
        *,
        evidence: tuple[str, ...] = (),
        payload: Mapping[str, object] | None = None,
    ) -> SelfFamilyProposal:
        if not isinstance(family, SelfFamily) or family not in self._definitions:
            raise ValueError("unknown_self_family")
        if not self.settings.enabled(family):
            raise PermissionError("self_family_disabled_by_settings")
        if not isinstance(summary, str) or not summary.strip():
            raise ValueError("self_family_proposal_summary_required")
        if not isinstance(evidence, tuple) or any(
            not isinstance(item, str) or not item.strip() for item in evidence
        ):
            raise ValueError("self_family_evidence_invalid")
        if payload is not None and not isinstance(payload, Mapping):
            raise TypeError("self_family_payload_must_be_mapping")

        canonical = json.dumps(
            {"family": family.value, "summary": summary.strip(),
             "evidence": list(evidence), "payload": dict(payload or {})},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()
        proposal_id = hashlib.sha256(
            (family.value + ":" + digest).encode("utf-8")
        ).hexdigest()[:24]
        return SelfFamilyProposal(
            proposal_id=proposal_id,
            family=family,
            summary=summary.strip(),
            evidence=evidence,
            payload_sha256=digest,
        )
