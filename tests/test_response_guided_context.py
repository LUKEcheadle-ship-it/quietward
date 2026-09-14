from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone

from quietward.contracts import AnalysisReport, EventKind, Finding, SecurityEvent, Severity
from quietward.integrations.response import build_response_handoff_events
from quietward.privacy_identity import PrivacyIdentity


class GuidedResponseContextTests(unittest.TestCase):
    def _build(self, *, severity: Severity, score: float, kinds: tuple[EventKind, ...]):
        observed = datetime(2026, 9, 9, 18, 0, tzinfo=timezone.utc)
        subject = r"C:\Users\alice\private\payload.exe"
        events = [
            SecurityEvent(
                event_id=f"event-{index}",
                observed_at=observed + timedelta(seconds=index),
                host_id="host-01",
                source=("process" if index % 2 == 0 else "network"),
                kind=kind,
                subject=subject,
                confidence=0.95,
            )
            for index, kind in enumerate(kinds, start=1)
        ]
        finding = Finding(
            finding_id="finding-guided-1",
            created_at=observed,
            host_id="host-01",
            subject=subject,
            title="Correlated security finding",
            summary="Sensitive local summary",
            score=score,
            severity=severity,
            evidence_event_ids=tuple(event.event_id for event in events),
            reasons=("process_network_corroboration=present", "cross_signal_actor_bonus=+6.0"),
        )
        report = AnalysisReport(
            generated_at=observed,
            mode="observe",
            events_analyzed=len(events),
            assessments=(),
            findings=(finding,),
            action_proposals=(),
            actions_executed=0,
        )
        return report, events, subject

    def test_high_confidence_multisignal_finding_exports_guided_triage_context(self) -> None:
        report, events, subject = self._build(
            severity=Severity.CRITICAL,
            score=94.0,
            kinds=(
                EventKind.MALWARE_SIGNATURE,
                EventKind.PROCESS_START,
                EventKind.OUTBOUND_CONNECTION,
            ),
        )
        payload = build_response_handoff_events(
            report,
            events,
            privacy_identity=PrivacyIdentity(b"r" * 32),
            operating_system="Windows 11",
        )[0]

        metadata = payload["metadata"]
        self.assertEqual(metadata["quietward_response_context_version"], "1.1")
        self.assertEqual(metadata["response_priority"], "urgent")
        self.assertEqual(metadata["evidence_strength"], "strong")
        self.assertEqual(metadata["recommended_playbook"], "malware_triage")
        self.assertIn("host_health", metadata["investigation_hints"])
        self.assertIn("process_inventory", metadata["investigation_hints"])
        self.assertIn("artifact_metadata_review", metadata["investigation_hints"])
        self.assertIs(metadata["executable_authority"], False)

        serialized = json.dumps(payload, sort_keys=True)
        self.assertNotIn(subject, serialized)
        self.assertNotIn('"target"', serialized)

    def test_single_low_signal_finding_remains_routine_and_limited(self) -> None:
        report, events, _ = self._build(
            severity=Severity.LOW,
            score=24.0,
            kinds=(EventKind.FILE_CHANGE,),
        )
        payload = build_response_handoff_events(
            report,
            events,
            privacy_identity=PrivacyIdentity(b"r" * 32),
        )[0]

        metadata = payload["metadata"]
        self.assertEqual(metadata["response_priority"], "routine")
        self.assertEqual(metadata["evidence_strength"], "limited")
        self.assertEqual(metadata["recommended_playbook"], "file_integrity_triage")


if __name__ == "__main__":
    unittest.main()
