from __future__ import annotations

import unittest
from datetime import datetime, timezone

from quietward.contracts import Finding, Severity
from quietward.integrations.forge import (
    build_forge_explanation_request,
    validate_forge_explanation_response,
)


class ForgeIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.finding = Finding(
            finding_id="finding",
            created_at=datetime.now(timezone.utc),
            host_id="host",
            subject="/tmp/a",
            title="Test",
            summary="Summary",
            score=70,
            severity=Severity.HIGH,
            evidence_event_ids=("evt",),
            reasons=("reason",),
        )

    def test_request_is_advisory_only(self) -> None:
        request = build_forge_explanation_request(self.finding)
        self.assertEqual(request["capability"], "advisory_only")
        self.assertFalse(request["constraints"]["may_execute_actions"])
        self.assertTrue(request["constraints"]["requires_human_approval"])

    def test_response_cannot_authorize_action(self) -> None:
        errors = validate_forge_explanation_response(
            {
                "explanation": "Evidence suggests investigation.",
                "recommended_next_steps": ["Review scanner evidence."],
                "uncertainty": "The behavior has not been independently confirmed.",
                "action_authorized": True,
            }
        )
        self.assertIn("micro-LLM responses cannot authorize actions", errors)

    def test_valid_response_passes(self) -> None:
        errors = validate_forge_explanation_response(
            {
                "explanation": "Evidence suggests investigation.",
                "recommended_next_steps": ["Review scanner evidence."],
                "uncertainty": "The behavior has not been independently confirmed.",
                "action_authorized": False,
            }
        )
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
