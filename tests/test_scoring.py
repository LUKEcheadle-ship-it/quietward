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


if __name__ == "__main__":
    unittest.main()
