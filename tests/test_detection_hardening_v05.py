from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from quietward.contracts import EventKind, SecurityEvent, Severity
from quietward.correlation import IncidentCorrelator
from quietward.scoring import DeterministicRiskScorer


NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)


def _event(
    event_id: str,
    kind: EventKind,
    subject: str,
    *,
    seconds: int = 0,
    attributes: dict | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        observed_at=NOW + timedelta(seconds=seconds),
        host_id="host-a",
        source="test",
        kind=kind,
        subject=subject,
        attributes=attributes or {},
        confidence=1.0,
    )


class DetectionHardeningV05Tests(unittest.TestCase):
    def test_high_signal_behavior_marker_receives_stronger_priority(self) -> None:
        result = DeterministicRiskScorer().score(
            _event(
                "evt-marker",
                EventKind.PROCESS_START,
                "proc-a",
                attributes={"suspicious_markers": ["reverse_shell"]},
            )
        )
        self.assertGreaterEqual(result.score, 35.0)
        self.assertIn("high_signal_markers=reverse_shell", result.reasons)

    def test_credential_spray_context_raises_auth_failure_score(self) -> None:
        result = DeterministicRiskScorer().score(
            _event(
                "evt-auth",
                EventKind.AUTH_FAILURE,
                "identity-source-hash",
                attributes={"failed_count": 64, "distinct_accounts": 20},
            )
        )
        self.assertGreaterEqual(result.score, 45.0)
        self.assertTrue(
            any(reason.startswith("credential_spray_context=20_accounts") for reason in result.reasons)
        )

    def test_cross_subject_three_phase_chain_becomes_high_priority(self) -> None:
        events = [
            _event(
                "evt-auth",
                EventKind.AUTH_FAILURE,
                "user-hash-a",
                attributes={"failed_count": 64, "distinct_accounts": 20},
            ),
            _event(
                "evt-priv",
                EventKind.PRIVILEGE_ESCALATION,
                "process-hash-a",
                seconds=120,
                attributes={"privileged_context": True},
            ),
            _event(
                "evt-persist",
                EventKind.PERSISTENCE_CHANGE,
                "task-hash-a",
                seconds=240,
                attributes={"persistence_indicator": True},
            ),
            _event(
                "evt-net",
                EventKind.OUTBOUND_CONNECTION,
                "connection-hash-a",
                seconds=360,
                attributes={"external_destination": True},
            ),
        ]
        scorer = DeterministicRiskScorer()
        findings = IncidentCorrelator().correlate(
            events,
            [scorer.score(event) for event in events],
        )
        chains = [finding for finding in findings if finding.finding_id.startswith("qwf-chain-")]
        self.assertEqual(len(chains), 1)
        self.assertIn(chains[0].severity, {Severity.HIGH, Severity.CRITICAL})
        self.assertIn("cross_subject_host_attack_chain=true", chains[0].reasons)
        self.assertTrue(any(reason.startswith("attack_chain_phases=") for reason in chains[0].reasons))

    def test_background_cross_subject_diversity_does_not_create_attack_chain(self) -> None:
        events = [
            _event("evt-proc", EventKind.PROCESS_START, "proc-a"),
            _event("evt-file", EventKind.FILE_CHANGE, "file-a", seconds=60),
            _event("evt-net", EventKind.OUTBOUND_CONNECTION, "net-a", seconds=120),
        ]
        scorer = DeterministicRiskScorer()
        findings = IncidentCorrelator().correlate(
            events,
            [scorer.score(event) for event in events],
        )
        self.assertFalse(any(item.finding_id.startswith("qwf-chain-") for item in findings))

    def test_attack_chain_window_is_bounded_to_fifteen_minutes(self) -> None:
        events = [
            _event("evt-mal", EventKind.MALWARE_SIGNATURE, "file-a"),
            _event("evt-net", EventKind.OUTBOUND_CONNECTION, "net-a", seconds=16 * 60),
        ]
        scorer = DeterministicRiskScorer()
        findings = IncidentCorrelator().correlate(
            events,
            [scorer.score(event) for event in events],
        )
        self.assertFalse(any(item.finding_id.startswith("qwf-chain-") for item in findings))


if __name__ == "__main__":
    unittest.main()
