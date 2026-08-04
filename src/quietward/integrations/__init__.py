"""Bounded external integration contracts."""

from .forge import build_forge_explanation_request, validate_forge_explanation_response
from .ollama import OllamaIncidentExplainer

__all__ = [
    "OllamaIncidentExplainer",
    "build_forge_explanation_request",
    "validate_forge_explanation_response",
]
