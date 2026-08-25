from __future__ import annotations

import unittest
from datetime import datetime, timezone

from quietward.contracts import EventKind, SecurityEvent, Severity
from quietward.scoring import DeterministicRiskScorer


def event(
    kind: EventKind,
    attributes: dict | None = None,
    confidence: float = 1.0,
) -> SecurityEvent:
    return SecurityEvent(
        event_id="evt",
        observed_at=datetime.now(timezone.utc),
        host_id="host",
        source="test",
        kind=kind,
        subject="subject",
        attributes=attributes or {},
        confidence=confidence,
    )


class RiskScoringTests(unittest.TestCase):
    def test_known_malware_is_critical(self) -> None:
        result = DeterministicRiskScorer().score(
            event(EventKind.MALWARE_SIGNATURE, {"known_bad_hash": True})
        )
        self.assertEqual(result.score, 100.0)
        self.assertEqual(result.severity, Severity.CRITICAL)

    def test_ordinary_process_start_is_informational(self) -> None:
        result = DeterministicRiskScorer().score(event(EventKind.PROCESS_START))
        self.assertEqual(result.severity, Severity.INFO)

    def test_repeated_auth_failures_raise_priority(self) -> None:
        result = DeterministicRiskScorer().score(
            event(
                EventKind.AUTH_FAILURE,
                {"failed_count": 64, "external_destination": True},
            )
        )
        self.assertGreaterEqual(result.score, 40.0)
        self.assertEqual(result.severity, Severity.MEDIUM)

    def test_listener_owner_markers_raise_priority(self) -> None:
        scorer = DeterministicRiskScorer()
        ordinary = scorer.score(
            event(
                EventKind.NEW_LISTENING_PORT,
                {
                    "external_bind": True,
                    "baseline_deviation": 1.0,
                },
                confidence=0.9,
            )
        )
        attributed = scorer.score(
            event(
                EventKind.NEW_LISTENING_PORT,
                {
                    "external_bind": True,
                    "baseline_deviation": 1.0,
                    "owner_suspicious_markers": ["user_writable_executable"],
                },
                confidence=0.9,
            )
        )
        self.assertEqual(attributed.score, ordinary.score + 10.0)
        self.assertIn("suspicious_markers=+10.0", attributed.reasons)

    def test_marker_sources_are_combined_without_duplicate_inflation(self) -> None:
        result = DeterministicRiskScorer().score(
            event(
                EventKind.PERSISTENCE_CHANGE,
                {
                    "risk_markers": ["user_writable_target", "network_target"],
                    "security_markers": ["network_target"],
                    "owner_suspicious_markers": ["user_writable_target"],
                },
            )
        )
        self.assertIn("suspicious_markers=+20.0", result.reasons)
        self.assertNotIn("suspicious_markers=+30.0", result.reasons)

    def test_marker_bonus_remains_capped(self) -> None:
        result = DeterministicRiskScorer().score(
            event(
                EventKind.FILE_CHANGE,
                {
                    "suspicious_markers": ["one", "two"],
                    "risk_markers": ["three", "four"],
                    "security_markers": ["five"],
                },
            )
        )
        self.assertIn("suspicious_markers=+30.0", result.reasons)


if __name__ == "__main__":
    unittest.main()
