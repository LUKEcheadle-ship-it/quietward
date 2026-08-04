from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from quietward.contracts import EventKind, SecurityEvent, Severity
from quietward.pipeline import SentinelPipeline


class PipelineTests(unittest.TestCase):
    def test_correlates_multiple_indicators_and_executes_nothing(self) -> None:
        now = datetime.now(timezone.utc)
        events = [
            SecurityEvent(
                event_id="one",
                observed_at=now,
                host_id="host",
                source="fim",
                kind=EventKind.EXECUTABLE_CREATED,
                subject="/tmp/suspicious",
                attributes={"unsigned_executable": True, "baseline_deviation": 0.8},
                confidence=0.95,
            ),
            SecurityEvent(
                event_id="two",
                observed_at=now + timedelta(seconds=1),
                host_id="host",
                source="network",
                kind=EventKind.OUTBOUND_CONNECTION,
                subject="/tmp/suspicious",
                attributes={"external_destination": True, "baseline_deviation": 0.9},
                confidence=0.9,
            ),
            SecurityEvent(
                event_id="three",
                observed_at=now + timedelta(seconds=2),
                host_id="host",
                source="yara",
                kind=EventKind.YARA_MATCH,
                subject="/tmp/suspicious",
                confidence=0.98,
            ),
        ]
        report = SentinelPipeline().analyze(events)
        self.assertEqual(report.events_analyzed, 3)
        self.assertEqual(report.actions_executed, 0)
        self.assertEqual(report.mode, "observe_only")
        self.assertEqual(len(report.findings), 1)
        self.assertIn(report.findings[0].severity, {Severity.HIGH, Severity.CRITICAL})
        self.assertTrue(report.action_proposals)
        self.assertTrue(
            all(not item.executable_in_current_mode for item in report.action_proposals)
        )

    def test_empty_input_returns_empty_report(self) -> None:
        report = SentinelPipeline().analyze([])
        self.assertEqual(report.events_analyzed, 0)
        self.assertEqual(report.findings, ())
        self.assertEqual(report.action_proposals, ())


if __name__ == "__main__":
    unittest.main()
