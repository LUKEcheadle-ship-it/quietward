from __future__ import annotations

import unittest
from datetime import datetime, timezone

from quietward.contracts import AnalysisReport, EventAssessment, EventKind, Finding, SecurityEvent, Severity
from quietward.integrations.response import build_response_handoff_events
from quietward.privacy_identity import PrivacyIdentity


def _fixture():
    observed = datetime(2026, 8, 31, 22, 0, tzinfo=timezone.utc)
    event = SecurityEvent(
        event_id="event-provenance-1",
        observed_at=observed,
        host_id="host-provenance",
        source="network",
        kind=EventKind.OUTBOUND_CONNECTION,
        subject="remote:203.0.113.9:443",
        attributes={"external_destination": True},
        confidence=1.0,
    )
    finding = Finding(
        finding_id="qwf-provenance-1",
        created_at=observed,
        host_id=event.host_id,
        subject=event.subject,
        title="Synthetic provenance finding",
        summary="Synthetic provenance summary",
        score=70.0,
        severity=Severity.HIGH,
        evidence_event_ids=(event.event_id,),
        reasons=("network_signal=+10",),
    )
    report = AnalysisReport(
        generated_at=observed,
        mode="observe_only",
        events_analyzed=1,
        assessments=(
            EventAssessment(
                event_id=event.event_id,
                score=70.0,
                severity=Severity.HIGH,
                reasons=("network_signal",),
            ),
        ),
        findings=(finding,),
        action_proposals=(),
        actions_executed=0,
    )
    return report, event


class ResponseHandoffProvenanceTests(unittest.TestCase):
    def test_valid_evidence_chain_provenance_is_embedded_without_raw_subject(self) -> None:
        report, event = _fixture()
        payload = build_response_handoff_events(
            report,
            [event],
            privacy_identity=PrivacyIdentity(b"p" * 32),
            source_cycle_id=42,
            source_chain_hash="a" * 64,
            operating_system="Linux",
        )[0]
        self.assertEqual(payload["metadata"]["quietward_source_cycle_id"], 42)
        self.assertEqual(payload["metadata"]["quietward_source_chain_hash"], "a" * 64)
        self.assertNotIn(event.subject, str(payload))
        self.assertNotIn("203.0.113.9", str(payload))

    def test_provenance_must_be_supplied_as_complete_pair(self) -> None:
        report, event = _fixture()
        with self.assertRaisesRegex(ValueError, "source evidence-chain hash"):
            build_response_handoff_events(
                report,
                [event],
                privacy_identity=PrivacyIdentity(b"p" * 32),
                source_cycle_id=42,
            )
        with self.assertRaisesRegex(ValueError, "source cycle id"):
            build_response_handoff_events(
                report,
                [event],
                privacy_identity=PrivacyIdentity(b"p" * 32),
                source_chain_hash="a" * 64,
            )

    def test_invalid_chain_hash_is_rejected(self) -> None:
        report, event = _fixture()
        with self.assertRaisesRegex(ValueError, "evidence-chain hash"):
            build_response_handoff_events(
                report,
                [event],
                privacy_identity=PrivacyIdentity(b"p" * 32),
                source_cycle_id=42,
                source_chain_hash="not-a-valid-chain-hash",
            )


if __name__ == "__main__":
    unittest.main()
