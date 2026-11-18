"""Model-runtime contracts; no model is loaded or network-called automatically."""
from nexora.intelligence.evaluation import EvaluationResult, evaluate_output
from nexora.intelligence.model_manager import ModelManager

__all__ = ["EvaluationResult", "ModelManager", "evaluate_output"]
