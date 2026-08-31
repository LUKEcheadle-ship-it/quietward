"""Bounded external integration contracts."""

from .forge import build_forge_explanation_request, validate_forge_explanation_response
from .ollama import OllamaIncidentExplainer
from .response import RESPONSE_CONTEXT_VERSION, build_response_handoff_events

__all__ = [
    "OllamaIncidentExplainer",
    "RESPONSE_CONTEXT_VERSION",
    "build_forge_explanation_request",
    "build_response_handoff_events",
    "validate_forge_explanation_response",
]
