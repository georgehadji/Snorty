"""Explain: a plain-English reading of an alert's rule from a model that runs on this PC."""

from snorty.explain.ollama import OllamaExplainer
from snorty.explain.ports import Explainer, ExplainError
from snorty.explain.service import ExplainService, Explanation

__all__ = ["ExplainError", "ExplainService", "Explainer", "Explanation", "OllamaExplainer"]
