from __future__ import annotations

import unittest
from datetime import datetime, timezone

from quietward.contracts import (
    EventAssessment,
    EventKind,
    SecurityEvent,
    Severity,
)
from quietward.correlation import IncidentCorrelator


NOW = datetime(2026, 8, 8, 7, 0, tzinfo=timezone.utc)


def assessment(event_id: str, score: float) -> EventAssessment:
    severity = (
        Severity.CRITICAL
        if score >= 85
        else Severity.HIGH
        if score >= 65
        else Severity.MEDIUM
        if score >= 40
        else Severity.LOW
        if score >= 15
        else Severity.INFO
    )
    return EventAssessment(event_id, score, severity, (f"score={score}",))


class CrossSignalCorrelationTests(unittest.TestCase):
    def test_matching_pid_links_process_and_listener_to_stronger_canonical_incident(self) -> None:
        process = SecurityEvent(
            "process",
            NOW,
            "host-a",
            "windows_process_snapshot",
            EventKind.PROCESS_START,
            "evil.exe",
            {"pid": 4242, "command_name": "evil.exe"},
        )
        listener = SecurityEvent(
            "listener",
            NOW,
            "host-a",
            "windows_socket_snapshot",
            EventKind.NEW_LISTENING_PORT,
            "tcp://*:4444",
            {"owner_pid": 4242, "owner_executable": "evil.exe"},
        )
        findings = IncidentCorrelator().correlate(
            [process, listener],
            [assessment("process", 20.0), assessment("listener", 60.0)],
        )
        by_subject = {item.subject: item for item in findings}
        canonical = by_subject["tcp://*:4444"]
        self.assertEqual(canonical.score, 66.0)
        self.assertEqual(canonical.severity, Severity.HIGH)
        self.assertEqual(
            canonical.evidence_event_ids,
            ("listener", "process"),
        )
        self.assertTrue(
            any("cross_signal_actor_bonus" in reason for reason in canonical.reasons)
        )
        self.assertEqual(
            by_subject["evil.exe"].evidence_event_ids,
            ("process",),
        )

    def test_distinctive_process_name_can_correlate_network_signals(self) -> None:
        listener = SecurityEvent(
            "listener",
            NOW,
            "host-a",
            "windows_socket_snapshot",
            EventKind.NEW_LISTENING_PORT,
            "tcp://*:8080",
            {"process_name": "odd-agent"},
        )
        outbound = SecurityEvent(
            "outbound",
            NOW,
            "host-a",
            "windows_outbound_connection_snapshot",
            EventKind.OUTBOUND_CONNECTION,
            "connection:odd-agent:dest:443",
            {"process_name": "odd-agent"},
        )
        findings = IncidentCorrelator().correlate(
            [listener, outbound],
            [assessment("listener", 50.0), assessment("outbound", 25.0)],
        )
        canonical = next(item for item in findings if item.subject == "tcp://*:8080")
        self.assertEqual(
            set(canonical.evidence_event_ids),
            {"listener", "outbound"},
        )
        self.assertTrue(
            any("cross_signal_actor_bonus" in reason for reason in canonical.reasons)
        )

    def test_generic_runtime_name_does_not_cross_correlate_unrelated_subjects(self) -> None:
        listener = SecurityEvent(
            "listener",
            NOW,
            "host-a",
            "windows_socket_snapshot",
            EventKind.NEW_LISTENING_PORT,
            "tcp://*:9000",
            {"process_name": "python"},
        )
        outbound = SecurityEvent(
            "outbound",
            NOW,
            "host-a",
            "windows_outbound_connection_snapshot",
            EventKind.OUTBOUND_CONNECTION,
            "connection:python:dest:443",
            {"process_name": "python"},
        )
        findings = IncidentCorrelator().correlate(
            [listener, outbound],
            [assessment("listener", 50.0), assessment("outbound", 25.0)],
        )
        for finding in findings:
            self.assertEqual(len(finding.evidence_event_ids), 1)
            self.assertFalse(
                any("cross_signal_actor_bonus" in reason for reason in finding.reasons)
            )


if __name__ == "__main__":
    unittest.main()
