from __future__ import annotations

import pytest

from nexora.intelligence.litertlm import (
    LiteRTLMError,
    find_executable,
    load_settings,
    model_inventory,
    run_local_model,
    runtime_status,
)


def test_missing_settings_use_disabled_safe_defaults(tmp_path):
    settings = load_settings(tmp_path / "missing.yaml")
    assert settings["runtime_enabled"] is False
    assert settings["network_downloads_enabled"] is False
    assert settings["presets_enabled"] is False


def test_settings_reject_unknown_fields(tmp_path):
    path = tmp_path / "litertlm.yaml"
    path.write_text("version: 1\nruntime_enabled: false\nunknown: true\n")
    with pytest.raises(LiteRTLMError, match="schema_invalid"):
        load_settings(path)


def test_settings_reject_network_downloads_and_presets(tmp_path):
    path = tmp_path / "litertlm.yaml"
    path.write_text(
        "version: 1\nruntime_enabled: false\nexecutable: litert-lm\n"
        "default_backend: cpu\nmodel_directory: models\ntimeout_seconds: 600\n"
        "network_downloads_enabled: true\npresets_enabled: false\n"
    )
    with pytest.raises(LiteRTLMError, match="network_downloads"):
        load_settings(path)


def test_inventory_only_lists_direct_litertlm_files(tmp_path):
    root = tmp_path / "models"
    root.mkdir()
    (root / "local.litertlm").write_bytes(b"model")
    (root / "ignore.bin").write_bytes(b"x")
    nested = root / "nested"
    nested.mkdir()
    (nested / "hidden.litertlm").write_bytes(b"y")
    assert [item["name"] for item in model_inventory(root)] == ["local.litertlm"]


def test_inventory_does_not_create_missing_directory(tmp_path):
    root = tmp_path / "not-created"
    assert model_inventory(root) == []
    assert not root.exists()


def test_run_requires_explicit_confirmation(tmp_path):
    model = tmp_path / "model.litertlm"
    model.write_bytes(b"model")
    with pytest.raises(LiteRTLMError, match="confirmation_required"):
        run_local_model(model, "hello")


def test_run_requires_enabled_setting(tmp_path):
    model = tmp_path / "model.litertlm"
    model.write_bytes(b"model")
    with pytest.raises(LiteRTLMError, match="runtime_disabled"):
        run_local_model(model, "hello", confirm_inference=True)


def test_run_rejects_non_litertlm_and_unknown_backend(tmp_path):
    model = tmp_path / "model.bin"
    model.write_bytes(b"model")
    with pytest.raises(LiteRTLMError, match="local_litertlm"):
        run_local_model(model, "hello", confirm_inference=True, runtime_enabled=True)
    valid = tmp_path / "model.litertlm"
    valid.write_bytes(b"model")
    with pytest.raises(LiteRTLMError, match="backend_invalid"):
        run_local_model(valid, "hello", backend="auto", confirm_inference=True,
                        runtime_enabled=True)


def test_status_is_read_only_and_safe(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "version: 1\nruntime_enabled: false\nexecutable: missing-litert-lm\n"
        "default_backend: cpu\nmodel_directory: " + str(tmp_path / "models") +
        "\ntimeout_seconds: 600\nnetwork_downloads_enabled: false\npresets_enabled: false\n"
    )
    result = runtime_status(config)
    assert result["installed"] is False
    assert result["models"] == []
    assert not (tmp_path / "models").exists()


def test_find_executable_uses_path_lookup(monkeypatch):
    monkeypatch.setattr("nexora.intelligence.litertlm.shutil.which", lambda value: "/bin/" + value)
    assert find_executable("litert-lm") == "/bin/litert-lm"



def test_run_uses_argument_vector_and_never_shell(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import nexora.intelligence.litertlm as adapter

    model = tmp_path / "model with spaces.litertlm"
    model.write_bytes(b"model")
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="answer", stderr="")

    monkeypatch.setattr(adapter, "find_executable", lambda _name: "/usr/bin/litert-lm")
    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    result = adapter.run_local_model(
        model, "hello; do not split me", backend="cpu",
        confirm_inference=True, runtime_enabled=True,
    )
    assert result == 0
    command, kwargs = calls[0]
    assert command[0] == "/usr/bin/litert-lm"
    assert command[1] == "run"
    assert "--backend=cpu" not in command
    assert "--prompt=hello; do not split me" in command
    assert kwargs["check"] is False
    assert kwargs["capture_output"] is True
    assert "shell" not in kwargs
