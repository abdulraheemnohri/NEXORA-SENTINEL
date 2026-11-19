import hashlib
import json

import pytest

from nexora.cli import main
from nexora.intelligence.model_catalog import build_model_catalog_report
from nexora.intelligence.provider_registry import (
    ProviderDescriptor,
    ProviderRegistry,
    ProviderRegistryError,
    build_provider_report,
)


def _write_catalog(path, models=None):
    import yaml

    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "runtime_enabled": False,
                "network_downloads_enabled": False,
                "default_provider": None,
                "models": [] if models is None else models,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _model_record(artifact="demo.litertlm", digest=None):
    return {
        "id": "demo-model",
        "provider": "litert-lm",
        "artifact": artifact,
        "format": "litertlm",
        "modalities": ["text"],
        "sha256": digest,
    }


def test_builtin_provider_registry_is_deterministic_and_non_executing():
    registry = ProviderRegistry(
        [
            ProviderDescriptor(
                provider_id="litert-lm",
                display_name="LiteRT-LM",
                adapter="nexora.intelligence.litertlm",
                modalities=("text",),
                capabilities=("text_generation",),
                local_inference=True,
                network_downloads_supported=True,
            )
        ]
    )

    assert [item.provider_id for item in registry.descriptors()] == ["litert-lm"]
    assert [item.provider_id for item in registry.compatible(["text_generation"])] == [
        "litert-lm"
    ]
    assert registry.get("litert-lm").automatic_execution is False


def test_provider_registry_rejects_duplicate_and_unqualified_capabilities():
    descriptor = ProviderDescriptor(
        provider_id="litert-lm",
        display_name="LiteRT-LM",
        adapter="nexora.intelligence.litertlm",
        modalities=("text",),
        capabilities=("text_generation",),
        local_inference=True,
        network_downloads_supported=True,
    )
    registry = ProviderRegistry([descriptor])
    with pytest.raises(ProviderRegistryError, match="already_registered"):
        registry.register(descriptor)
    with pytest.raises(ProviderRegistryError, match="not_qualified"):
        registry.compatible(["tool_execution"])


def test_provider_registry_rejects_automatic_execution_and_malformed_values():
    with pytest.raises(ProviderRegistryError, match="must_remain_disabled"):
        ProviderDescriptor(
            provider_id="litert-lm",
            display_name="LiteRT-LM",
            adapter="nexora.intelligence.litertlm",
            modalities=("text",),
            capabilities=("text_generation",),
            local_inference=True,
            network_downloads_supported=True,
            automatic_execution=True,
        ).validate()
    with pytest.raises(ProviderRegistryError, match="modalities_invalid"):
        ProviderDescriptor(
            provider_id="bad-provider",
            display_name="Bad",
            adapter="bad",
            modalities=(["text"],),
            capabilities=("text_generation",),
            local_inference=True,
            network_downloads_supported=False,
        ).validate()


def test_provider_report_is_metadata_only_and_defaults_disabled(tmp_path):
    report = build_provider_report(tmp_path / "missing.yaml")
    assert report["status"] == "OK"
    assert report["count"] == 1
    provider = report["providers"][0]
    assert provider["provider_id"] == "litert-lm"
    assert provider["runtime_enabled_in_config"] is False
    assert provider["network_downloads_enabled_in_config"] is False
    assert provider["automatic_execution"] is False
    assert provider["model_loading"] is False


def test_model_catalog_accepts_empty_default_catalog_without_creating_model_dir(tmp_path):
    config = tmp_path / "models.yaml"
    model_dir = tmp_path / "not-created"
    _write_catalog(config)

    report = build_model_catalog_report(config, model_dir=model_dir)

    assert report["status"] == "EMPTY"
    assert report["valid"] is True
    assert report["count"] == 0
    assert report["execution_enabled"] is False
    assert not model_dir.exists()


def test_model_catalog_verifies_declared_sha256(tmp_path):
    config = tmp_path / "models.yaml"
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    artifact = model_dir / "demo.litertlm"
    artifact.write_bytes(b"known test model bytes")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    _write_catalog(config, [_model_record(digest=digest)])

    report = build_model_catalog_report(config, model_dir=model_dir)

    assert report["status"] == "VALID"
    assert report["models"][0]["file_status"] == "PRESENT"
    assert report["models"][0]["integrity"] == "VERIFIED"
    assert report["models"][0]["execution_eligible"] is False


def test_model_catalog_marks_hash_mismatch_untrusted(tmp_path):
    config = tmp_path / "models.yaml"
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    (model_dir / "demo.litertlm").write_bytes(b"changed bytes")
    _write_catalog(config, [_model_record(digest="0" * 64)])

    report = build_model_catalog_report(config, model_dir=model_dir)

    assert report["status"] == "VALID"
    assert report["models"][0]["integrity"] == "HASH_MISMATCH"
    assert report["models"][0]["authorization"] == "NOT_GRANTED"
    assert report["execution_enabled"] is False


@pytest.mark.parametrize(
    "artifact",
    ["../outside.litertlm", "/absolute.litertlm", r"..\outside.litertlm"],
)
def test_model_catalog_rejects_traversal_and_absolute_paths(tmp_path, artifact):
    config = tmp_path / "models.yaml"
    _write_catalog(config, [_model_record(artifact=artifact)])

    report = build_model_catalog_report(config, model_dir=tmp_path / "models")

    assert report["status"] == "INVALID"
    assert "artifact_path" in report["error"]


def test_model_catalog_rejects_unknown_provider_and_duplicate_ids(tmp_path):
    config = tmp_path / "models.yaml"
    unknown = _model_record()
    unknown["provider"] = "unregistered-provider"
    _write_catalog(config, [unknown])
    report = build_model_catalog_report(config, model_dir=tmp_path / "models")
    assert report["status"] == "INVALID"
    assert report["error"] == "provider_not_registered"

    _write_catalog(config, [_model_record(), _model_record(artifact="second.litertlm")])
    report = build_model_catalog_report(config, model_dir=tmp_path / "models")
    assert report["status"] == "INVALID"
    assert report["error"] == "model_id_duplicate"


def test_model_catalog_rejects_symlinked_artifact(tmp_path):
    config = tmp_path / "models.yaml"
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    target = tmp_path / "target.litertlm"
    target.write_bytes(b"model")
    link = model_dir / "demo.litertlm"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("file symlinks unavailable")
    _write_catalog(config, [_model_record()])

    report = build_model_catalog_report(config, model_dir=model_dir)

    assert report["models"][0]["file_status"] == "SYMLINK_REJECTED"
    assert report["models"][0]["integrity"] == "UNVERIFIED"


def test_model_catalog_rejects_symlinked_model_root(tmp_path):
    config = tmp_path / "models.yaml"
    real_root = tmp_path / "real-models"
    real_root.mkdir()
    linked_root = tmp_path / "linked-models"
    try:
        linked_root.symlink_to(real_root, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks unavailable")
    _write_catalog(config, [_model_record()])

    report = build_model_catalog_report(config, model_dir=linked_root)

    assert report["status"] == "INVALID"
    assert report["error"] == "model_root_symlink_rejected"


def test_model_catalog_rejects_malformed_top_level_schema(tmp_path):
    config = tmp_path / "models.yaml"
    config.write_text("version: 1\nmodels: []\n", encoding="utf-8")

    report = build_model_catalog_report(config, model_dir=tmp_path / "models")

    assert report["status"] == "INVALID"
    assert report["error"] == "model_catalog_schema_invalid"


def test_provider_and_model_cli_commands_are_read_only(tmp_path, capsys):
    result = main(["providers", "--config", str(tmp_path / "missing-litertlm.yaml")])
    providers = json.loads(capsys.readouterr().out)
    assert result == 0
    assert providers["automatic_execution"] is False

    config = tmp_path / "models.yaml"
    _write_catalog(config)
    model_dir = tmp_path / "not-created"
    result = main(["models", "catalog", "--config", str(config), "--model-dir", str(model_dir)])
    models = json.loads(capsys.readouterr().out)
    assert result == 0
    assert models["status"] == "EMPTY"
    assert not model_dir.exists()
