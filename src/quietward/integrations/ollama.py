from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from .forge import validate_forge_explanation_response
from ..alerts import DeterministicExplainer
from ..config import MicroLLMSettings


class OllamaIncidentExplainer:
    """Optional localhost-only micro-LLM explanation client with deterministic fallback."""

    def __init__(self, settings: MicroLLMSettings, opener: Callable[..., Any] = urllib.request.urlopen) -> None:
        if not settings.enabled or not settings.model:
            raise ValueError("Ollama explainer requires an enabled model configuration")
        parsed = urllib.parse.urlparse(settings.endpoint)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("micro-LLM endpoint must be localhost HTTP")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("micro-LLM endpoint may not contain credentials, query, or fragment")
        self.settings = settings
        self.opener = opener
        self.fallback = DeterministicExplainer()

    def explain(self, finding: dict[str, Any]) -> dict[str, Any]:
        request_payload = {
            "model": self.settings.model,
            "stream": False,
            "format": "json",
            "prompt": json.dumps({
                "task": "Explain this normalized security finding for a human operator.",
                "finding": finding,
                "required_output": {"explanation": "string", "recommended_next_steps": ["up to five non-destructive investigation steps"], "uncertainty": "string", "action_authorized": False},
                "constraints": {"scanner_evidence_is_authoritative": True, "do_not_invent_evidence": True, "do_not_authorize_actions": True, "do_not_request_secrets": True},
            }, sort_keys=True),
            "options": {"temperature": 0.1, "num_predict": 700},
        }
        endpoint = self.settings.endpoint.rstrip("/") + "/api/generate"
        request = urllib.request.Request(endpoint, data=json.dumps(request_payload).encode("utf-8"), headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
        try:
            with self.opener(request, timeout=self.settings.timeout_seconds) as response:
                if getattr(response, "status", 200) != 200:
                    raise ValueError(f"micro-LLM returned HTTP {response.status}")
                raw = response.read(128_000)
            envelope = json.loads(raw)
            response_text = envelope.get("response") if isinstance(envelope, dict) else None
            value = json.loads(response_text) if isinstance(response_text, str) else response_text
            if not isinstance(value, dict):
                raise ValueError("micro-LLM response was not an object")
            errors = validate_forge_explanation_response(value)
            if errors:
                raise ValueError("; ".join(errors))
            value = dict(value)
            value["action_authorized"] = False
            value["source"] = "ollama_local_micro_llm"
            return value
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
            result = self.fallback.explain(finding)
            result["fallback_used"] = True
            return result
