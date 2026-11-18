"""Managed adapter for Google's official LiteRT-LM command-line runtime.

NEXORA never shells out through a command string, never executes model presets,
and never downloads model weights through this adapter. Runtime installation and
local inference require explicit operator confirmation.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml


class LiteRTLMError(RuntimeError):
    """A fail-closed LiteRT-LM integration error."""


DEFAULT_SETTINGS: dict[str, Any] = {
    "version": 1,
    "runtime_enabled": False,
    "executable": "litert-lm",
    "default_backend": "cpu",
    "model_directory": "models",
    "timeout_seconds": 600,
    "network_downloads_enabled": False,
    "presets_enabled": False,
}


def load_settings(path: Path = Path("config/litertlm.yaml")) -> dict[str, Any]:
    """Load strict runtime settings; missing files use disabled defaults."""
    source = Path(path)
    if not source.exists():
        return dict(DEFAULT_SETTINGS)
    if not source.is_file():
        raise LiteRTLMError("litertlm_settings_not_a_file")
    try:
        value = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise LiteRTLMError("litertlm_settings_invalid") from exc
    if not isinstance(value, dict) or set(value) != set(DEFAULT_SETTINGS):
        raise LiteRTLMError("litertlm_settings_schema_invalid")
    if value.get("version") != 1:
        raise LiteRTLMError("litertlm_settings_version_unsupported")
    if type(value.get("runtime_enabled")) is not bool:
        raise LiteRTLMError("litertlm_runtime_enabled_must_be_boolean")
    if type(value.get("network_downloads_enabled")) is not bool or value["network_downloads_enabled"]:
        raise LiteRTLMError("litertlm_network_downloads_must_remain_disabled")
    if type(value.get("presets_enabled")) is not bool or value["presets_enabled"]:
        raise LiteRTLMError("litertlm_presets_must_remain_disabled")
    if value.get("default_backend") not in {"cpu", "gpu"}:
        raise LiteRTLMError("litertlm_backend_invalid")
    if not isinstance(value.get("executable"), str) or not value["executable"].strip():
        raise LiteRTLMError("litertlm_executable_invalid")
    if not isinstance(value.get("model_directory"), str) or not value["model_directory"].strip():
        raise LiteRTLMError("litertlm_model_directory_invalid")
    timeout = value.get("timeout_seconds")
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise LiteRTLMError("litertlm_timeout_out_of_range")
    return value


def find_executable(executable: str = "litert-lm") -> str | None:
    """Resolve the configured CLI without invoking a shell."""
    return shutil.which(executable)


def model_inventory(model_directory: Path) -> list[dict[str, Any]]:
    """List direct, regular local .litertlm files without creating directories."""
    root = Path(model_directory)
    if not root.is_dir():
        return []
    entries = []
    for path in sorted(root.iterdir(), key=lambda item: item.name.casefold()):
        if path.is_symlink() or not path.is_file() or path.suffix.lower() != ".litertlm":
            continue
        try:
            entries.append({
                "name": path.name,
                "path": str(path.resolve()),
                "bytes": path.stat().st_size,
                "runtime": "NOT_LOADED",
            })
        except OSError:
            continue
    return entries


def runtime_status(
    config_path: Path = Path("config/litertlm.yaml"),
) -> dict[str, Any]:
    settings = load_settings(config_path)
    executable = find_executable(settings["executable"])
    model_dir = Path(settings["model_directory"])
    return {
        "provider": "LiteRT-LM",
        "runtime_enabled": settings["runtime_enabled"],
        "installed": executable is not None,
        "executable": executable,
        "default_backend": settings["default_backend"],
        "model_directory": str(model_dir),
        "models": model_inventory(model_dir),
        "network_downloads_enabled": settings["network_downloads_enabled"],
        "presets_enabled": settings["presets_enabled"],
        "inference_requires": ["runtime_enabled=true", "--confirm-inference"],
        "installation_command": "python -m pip install --upgrade litert-lm",
        "execution": "local_cli_subprocess_no_shell",
    }


def install_cli(*, confirm: bool, python_executable: str = sys.executable,
                timeout: int = 1800) -> dict[str, Any]:
    """Install official CLI into the active Python environment after confirmation."""
    if not confirm:
        raise LiteRTLMError("runtime_install_confirmation_required")
    if timeout < 1 or timeout > 3600:
        raise LiteRTLMError("runtime_install_timeout_out_of_range")
    command = [python_executable, "-m", "pip", "install", "--upgrade", "litert-lm"]
    try:
        result = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise LiteRTLMError("runtime_install_timed_out") from exc
    except OSError as exc:
        raise LiteRTLMError("runtime_install_could_not_start") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "")[-3000:]
        raise LiteRTLMError("runtime_install_failed: " + detail)
    return {"installed": True, "package": "litert-lm", "python": python_executable}


def run_local_model(
    model: Path,
    prompt: str | None = None,
    *,
    backend: str = "cpu",
    executable: str = "litert-lm",
    timeout: int = 600,
    confirm_inference: bool = False,
    runtime_enabled: bool = False,
    interactive: bool = False,
) -> int:
    """Run a local model only; no HF identifiers, downloads, presets, or shell."""
    if not confirm_inference:
        raise LiteRTLMError("inference_confirmation_required")
    if not runtime_enabled:
        raise LiteRTLMError("litertlm_runtime_disabled_in_settings")
    if backend not in {"cpu", "gpu"}:
        raise LiteRTLMError("litertlm_backend_invalid")
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise LiteRTLMError("litertlm_timeout_out_of_range")
    target = Path(model).expanduser()
    if not target.is_file() or target.suffix.lower() != ".litertlm":
        raise LiteRTLMError("local_litertlm_model_file_required")
    resolved = target.resolve()
    binary = find_executable(executable)
    if binary is None:
        raise LiteRTLMError("litertlm_cli_not_installed")
    command = [binary, "run", str(resolved)]
    if backend == "gpu":
        command.append("--backend=gpu")
    if prompt is not None:
        if not prompt.strip():
            raise LiteRTLMError("prompt_must_not_be_empty")
        command.append("--prompt=" + prompt)
    try:
        result = subprocess.run(
            command, check=False, timeout=timeout,
            text=True, capture_output=not interactive,
        )
    except subprocess.TimeoutExpired as exc:
        raise LiteRTLMError("litertlm_inference_timed_out") from exc
    except OSError as exc:
        raise LiteRTLMError("litertlm_cli_could_not_start") from exc
    if not interactive:
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
    return result.returncode
