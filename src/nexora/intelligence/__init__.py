"""Model-runtime contracts; no model is loaded or network-called automatically."""
from nexora.intelligence.evaluation import EvaluationResult, evaluate_output
from nexora.intelligence.model_catalog import ModelCatalogError, build_model_catalog_report
from nexora.intelligence.model_manager import ModelManager
from nexora.intelligence.provider_registry import (
    ProviderDescriptor,
    ProviderRegistry,
    ProviderRegistryError,
    build_provider_report,
)

__all__ = [
    "EvaluationResult",
    "ModelCatalogError",
    "ModelManager",
    "ProviderDescriptor",
    "ProviderRegistry",
    "ProviderRegistryError",
    "build_model_catalog_report",
    "build_provider_report",
    "evaluate_output",
]
