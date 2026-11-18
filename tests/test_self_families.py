import pytest

from nexora.self_families import (
    SELF_FAMILIES,
    SelfFamily,
    SelfFamilyManager,
    SelfFamilySettings,
)


def test_self_family_catalogue_is_explicitly_proposal_only():
    assert len(SELF_FAMILIES) == 6
    assert all(not item.may_mutate for item in SELF_FAMILIES)
    assert all(not item.may_execute for item in SELF_FAMILIES)
    assert all(not item.may_self_enable for item in SELF_FAMILIES)


def test_observation_and_diagnostics_enabled_by_default():
    manager = SelfFamilyManager()
    assert manager.settings.enabled(SelfFamily.OBSERVATION)
    assert manager.settings.enabled(SelfFamily.DIAGNOSTICS)
    assert not manager.settings.enabled(SelfFamily.REPAIR_PLANNING)
    assert not manager.settings.enabled(SelfFamily.LEARNING)
    assert not manager.settings.enabled(SelfFamily.GOVERNANCE_ASSISTANCE)
    assert not manager.settings.enabled(SelfFamily.EVOLUTION)


def test_disabled_self_family_fails_closed():
    manager = SelfFamilyManager()
    with pytest.raises(PermissionError, match="disabled_by_settings"):
        manager.propose(SelfFamily.EVOLUTION, "Propose a code refactor")


def test_enabled_family_returns_deterministic_review_proposal():
    manager = SelfFamilyManager(SelfFamilySettings(evolution_enabled=True))
    first = manager.propose(
        SelfFamily.EVOLUTION, "Refactor diagnostics",
        evidence=("issue:42",), payload={"scope": "diagnostics only"},
    )
    second = manager.propose(
        SelfFamily.EVOLUTION, "Refactor diagnostics",
        evidence=("issue:42",), payload={"scope": "diagnostics only"},
    )
    assert first == second
    assert first.status == "PENDING_HUMAN_REVIEW"
    assert first.execution == "DISABLED"
    assert len(first.payload_sha256) == 64


def test_proposal_rejects_empty_summary_and_invalid_evidence():
    manager = SelfFamilyManager()
    with pytest.raises(ValueError, match="summary_required"):
        manager.propose(SelfFamily.OBSERVATION, " ")
    with pytest.raises(ValueError, match="evidence_invalid"):
        manager.propose(SelfFamily.OBSERVATION, "snapshot", evidence=("ok", 7))


def test_settings_reject_runtime_autonomy_escalation():
    with pytest.raises(ValueError, match="autonomy_must_be_L0_or_L1"):
        SelfFamilySettings(autonomy_level="L2").validate()
    with pytest.raises(ValueError, match="flags_must_be_boolean"):
        SelfFamilySettings(learning_enabled=1).validate()
