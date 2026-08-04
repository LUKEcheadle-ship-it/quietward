from __future__ import annotations

import json
import unittest

from quietward.config import MicroLLMSettings
from quietward.integrations.ollama import OllamaIncidentExplainer


class Response:
    status = 200

    def __init__(self, value: dict[str, object]) -> None:
        self.data = json.dumps(value).encode()

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.data[:limit]


class OllamaIntegrationTests(unittest.TestCase):
    def test_nonlocal_endpoint_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "localhost"):
            OllamaIncidentExplainer(
                MicroLLMSettings(True, "https://example.com", "model", 1)
            )

    def test_valid_response_remains_advisory(self) -> None:
        result = {
            "explanation": "Evidence suggests suspicious behavior.",
            "recommended_next_steps": ["Review the event."],
            "uncertainty": "Intent is unknown.",
            "action_authorized": False,
        }
        opener = lambda *args, **kwargs: Response(
            {"response": json.dumps(result)}
        )
        explained = OllamaIncidentExplainer(
            MicroLLMSettings(True, "http://127.0.0.1:11434", "tiny", 1),
            opener=opener,
        ).explain({"finding_id": "f1", "severity": "high"})
        self.assertEqual(explained["source"], "ollama_local_micro_llm")
        self.assertFalse(explained["action_authorized"])

    def test_invalid_response_uses_fallback(self) -> None:
        opener = lambda *args, **kwargs: Response({"response": "not-json"})
        explained = OllamaIncidentExplainer(
            MicroLLMSettings(True, "http://localhost:11434", "tiny", 1),
            opener=opener,
        ).explain({"subject": "test", "severity": "high"})
        self.assertTrue(explained["fallback_used"])
        self.assertFalse(explained["action_authorized"])


if __name__ == "__main__":
    unittest.main()
