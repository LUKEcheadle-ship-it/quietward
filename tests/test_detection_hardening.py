from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from quietward.contracts import EventKind, SecurityEvent, Severity
from quietward.correlation import IncidentCorrelator
from quietward.scoring import DeterministicRiskScorer


def event(
    event_id: str,
    kind: EventKind,
    subject: str,
    *,
    observed_at: datetime,
    attributes: dict | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        observed_at=observed_at,
        host_id="host-a",
        source="test",
        kind=kind,
        subject=subject,
        attributes=attributes or {},
        confidence=1.0,
    )


class DetectionHardeningTests(unittest.TestCase):
    def test_cross_subject_multistage_chain_becomes_one_host_finding(self) -> None:
        start = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
        events = [
            event("e1", EventKind.AUTH_FAILURE, "acct:alice", observed_at=start, attributes={"failed_count": 64}),
            event("e2", EventKind.PRIVILEGE_ESCALATION, "proc:123", observed_at=start + timedelta(minutes=3)),
            event("e3", EventKind.PERSISTENCE_CHANGE, "task:startup", observed_at=start + timedelta(minutes=6)),
            event("e4", EventKind.OUTBOUND_CONNECTION, "conn:remote", observed_at=start + timedelta(minutes=8), attributes={"external_destination": True}),
        ]
        scorer = DeterministicRiskScorer()
        assessments = [scorer.score(item) for item in events]
        findings = IncidentCorrelator().correlate(events, assessments)

        chains = [item for item in findings if item.finding_id.startswith("qwf-chain-")]
        self.assertEqual(len(chains), 1)
        chain = chains[0]
        self.assertIn(chain.severity, {Severity.HIGH, Severity.CRITICAL})
        self.assertEqual(set(chain.evidence_event_ids), {"e1", "e2", "e3", "e4"})
        self.assertIn("cross_subject_host_attack_chain=true", chain.reasons)

    def test_same_events_outside_window_do_not_form_chain(self) -> None:
        start = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
        events = [
            event("e1", EventKind.PRIVILEGE_ESCALATION, "proc:123", observed_at=start),
            event("e2", EventKind.PERSISTENCE_CHANGE, "task:startup", observed_at=start + timedelta(minutes=20)),
            event("e3", EventKind.OUTBOUND_CONNECTION, "conn:remote", observed_at=start + timedelta(minutes=40)),
        ]
        scorer = DeterministicRiskScorer()
        findings = IncidentCorrelator().correlate(events, [scorer.score(item) for item in events])
        self.assertFalse(any(item.finding_id.startswith("qwf-chain-") for item in findings))

    def test_high_signal_behavior_markers_raise_process_priority(self) -> None:
        sample = event(
            "e1",
            EventKind.PROCESS_START,
            "proc:123",
            observed_at=datetime.now(timezone.utc),
            attributes={"security_markers": ["reverse_shell", "encoded_command"]},
        )
        assessment = DeterministicRiskScorer().score(sample)
        self.assertGreaterEqual(assessment.score, 50.0)
        self.assertIn(assessment.severity, {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL})
        self.assertTrue(any("high_signal_markers=" in reason for reason in assessment.reasons))

    def test_credential_spray_context_raises_auth_priority(self) -> None:
        sample = event(
            "e1",
            EventKind.AUTH_FAILURE,
            "auth-source:hash",
            observed_at=datetime.now(timezone.utc),
            attributes={
                "failed_count": 64,
                "distinct_accounts": 12,
                "security_markers": ["credential_spray"],
            },
        )
        assessment = DeterministicRiskScorer().score(sample)
        self.assertIn(assessment.severity, {Severity.HIGH, Severity.CRITICAL})
        self.assertTrue(any("credential_spray_context=" in reason for reason in assessment.reasons))


if __name__ == "__main__":
    unittest.main()
