"""Explicit provider registry for local model adapter discovery.

The registry describes adapters and their declared capabilities. It does not
instantiate a model, download weights, run inference, invoke tools, or grant
execution authority.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from nexora.intelligence.litertlm import LiteRTLMError, runtime_status

_PROVIDER_ID = re.compile(r"^[a-z][a-z0-9._-]{1,63}$")
_ALLOWED_CAPABILITIES = frozenset({"text_generation"})
_ALLOWED_MODALITIES = frozenset({"text"})


class ProviderRegistryError(ValueError):
    """Invalid or ambiguous provider registration."""


@dataclass(frozen=True)
class ProviderDescriptor:
    provider_id: str
    display_name: str
    adapter: str
    modalities: tuple[str, ...]
    capabilities: tuple[str, ...]
    local_inference: bool
    network_downloads_supported: bool
    automatic_execution: bool = False

    def validate(self) -> "ProviderDescriptor":
        if not isinstance(self.provider_id, str) or not _PROVIDER_ID.fullmatch(self.provider_id):
            raise ProviderRegistryError("provider_id_invalid")
        if not isinstance(self.display_name, str) or not self.display_name.strip():
            raise ProviderRegistryError("provider_display_name_required")
        if not isinstance(self.adapter, str) or not self.adapter.strip():
            raise ProviderRegistryError("provider_adapter_required")
        if type(self.local_inference) is not bool or type(self.network_downloads_supported) is not bool:
            raise ProviderRegistryError("provider_flags_must_be_boolean")
        if type(self.automatic_execution) is not bool or self.automatic_execution:
            raise ProviderRegistryError("automatic_provider_execution_must_remain_disabled")
        if (
            not isinstance(self.modalities, (tuple, list))
            or not self.modalities
            or any(not isinstance(item, str) for item in self.modalities)
            or len(set(self.modalities)) != len(self.modalities)
        ):
            raise ProviderRegistryError("provider_modalities_invalid")
        if any(item not in _ALLOWED_MODALITIES for item in self.modalities):
            raise ProviderRegistryError("provider_modality_not_qualified")
        if (
            not isinstance(self.capabilities, (tuple, list))
            or not self.capabilities
            or any(not isinstance(item, str) for item in self.capabilities)
            or len(set(self.capabilities)) != len(self.capabilities)
        ):
            raise ProviderRegistryError("provider_capabilities_invalid")
        if any(item not in _ALLOWED_CAPABILITIES for item in self.capabilities):
            raise ProviderRegistryError("provider_capability_not_qualified")
        return self


class ProviderRegistry:
    """Deterministic in-memory registry; registration is not execution approval."""

    def __init__(self, descriptors: Iterable[ProviderDescriptor] = ()):
        self._providers: dict[str, ProviderDescriptor] = {}
        for descriptor in descriptors:
            self.register(descriptor)

    def register(self, descriptor: ProviderDescriptor) -> None:
        if not isinstance(descriptor, ProviderDescriptor):
            raise ProviderRegistryError("provider_descriptor_required")
        descriptor.validate()
        if descriptor.provider_id in self._providers:
            raise ProviderRegistryError("provider_id_already_registered")
        self._providers[descriptor.provider_id] = descriptor

    def get(self, provider_id: str) -> ProviderDescriptor:
        try:
            return self._providers[provider_id]
        except KeyError as exc:
            raise ProviderRegistryError("provider_not_registered") from exc

    def compatible(self, required: Iterable[str]) -> list[ProviderDescriptor]:
        requested = tuple(required)
        if any(
            not isinstance(item, str) or item not in _ALLOWED_CAPABILITIES
            for item in requested
        ):
            raise ProviderRegistryError("requested_capability_not_qualified")
        return [
            descriptor
            for descriptor in self._providers.values()
            if set(requested).issubset(descriptor.capabilities)
        ]

    def descriptors(self) -> list[ProviderDescriptor]:
        return [self._providers[key] for key in sorted(self._providers)]


def builtin_registry() -> ProviderRegistry:
    """Return only adapters with a concrete, source-backed implementation."""
    return ProviderRegistry((
        ProviderDescriptor(
            provider_id="litert-lm",
            display_name="Google LiteRT-LM",
            adapter="nexora.intelligence.litertlm",
            modalities=("text",),
            capabilities=("text_generation",),
            local_inference=True,
            network_downloads_supported=True,
            automatic_execution=False,
        ),
    ))


def build_provider_report(config_path: Path = Path("config/litertlm.yaml")) -> dict:
    """Describe known adapters and runtime presence without loading a model."""
    try:
        runtime = runtime_status(Path(config_path))
    except (LiteRTLMError, OSError, ValueError) as exc:
        return {
            "status": "INVALID_RUNTIME_CONFIGURATION",
            "providers": [],
            "error": str(exc),
            "model_loading": False,
            "automatic_execution": False,
        }

    rows = []
    for descriptor in builtin_registry().descriptors():
        rows.append({
            **asdict(descriptor),
            "modalities": list(descriptor.modalities),
            "capabilities": list(descriptor.capabilities),
            "installed": runtime["installed"],
            "runtime_enabled_in_config": runtime["runtime_enabled"],
            "network_downloads_enabled_in_config": runtime["network_downloads_enabled"],
            "model_loading": False,
            "automatic_execution": False,
            "manual_inference_confirmation_required": True,
        })
    return {
        "status": "OK",
        "count": len(rows),
        "providers": rows,
        "model_loading": False,
        "automatic_execution": False,
        "note": "Provider discovery is metadata only; runtime configuration is not an execution authorization.",
    }
