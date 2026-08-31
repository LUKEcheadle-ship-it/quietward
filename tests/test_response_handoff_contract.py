from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from uuid import UUID

from quietward.contracts import (
    ActionProposal,
    ActionType,
    AnalysisReport,
    EventAssessment,
    EventKind,
    Finding,
    SecurityEvent,
    Severity,
)
from quietward.integrations.response import build_response_handoff_events
from quietward.privacy_identity import PrivacyIdentity


def _fixture(*, executable: bool = False, host_id: str = "host-01"):
    observed = datetime(2026, 8, 31, 20, 0, tzinfo=timezone.utc)
    sensitive_subject = "/home/alice/private/quarterly-plan.docx"
    event = SecurityEvent(
        event_id="event-sensitive-1",
        observed_at=observed,
        host_id=host_id,
        source="filesystem",
        kind=EventKind.EXECUTABLE_CREATED,
        subject=sensitive_subject,
        attributes={"owner_executable": "/usr/bin/python3"},
        confidence=0.91,
    )
    finding = Finding(
        finding_id="qwf-sensitive-1",
        created_at=observed,
        host_id=host_id,
        subject=sensitive_subject,
        title=f"Potential security incident involving {sensitive_subject}",
        summary=f"Sensitive subject: {sensitive_subject}",
        score=82.0,
        severity=Severity.HIGH,
        evidence_event_ids=(event.event_id,),
        reasons=(
            "cross_signal_actor_bonus=+6.0",
            "process_network_corroboration=python3",
            "human readable reason containing sensitive data",
        ),
    )
    proposal = ActionProposal(
        proposal_id="fsp-1",
        finding_id=finding.finding_id,
        action_type=ActionType.QUARANTINE_ARTIFACT,
        target=sensitive_subject,
        reason="proposed locally only",
        destructive=True,
        executable_in_current_mode=executable,
    )
    report = AnalysisReport(
        generated_at=observed,
        mode="observe",
        events_analyzed=1,
        assessments=(
            EventAssessment(
                event_id=event.event_id,
                score=82.0,
                severity=Severity.HIGH,
                reasons=("known_sensitive_signal",),
            ),
        ),
        findings=(finding,),
        action_proposals=(proposal,),
        actions_executed=0,
    )
    return report, event, sensitive_subject


class ResponseHandoffContractTests(unittest.TestCase):
    def test_handoff_is_response_compatible_and_does_not_leak_raw_subject(self) -> None:
        report, event, sensitive_subject = _fixture()
        identity = PrivacyIdentity(b"k" * 32)

        payloads = build_response_handoff_events(
            report,
            [event],
            privacy_identity=identity,
            source_version="0.6.0-alpha.1",
            operating_system="Linux",
        )

        self.assertEqual(len(payloads), 1)
        payload = payloads[0]
        UUID(payload["event_id"])
        self.assertEqual(payload["schema_version"], "1.0")
        self.assertEqual(payload["source"], "quietward")
        self.assertEqual(payload["host_id"], "host-01")
        self.assertEqual(payload["category"], "execution")
        self.assertEqual(payload["severity"], "high")
        self.assertIs(payload["metadata"]["observation_only_source"], True)
        self.assertIs(payload["metadata"]["executable_authority"], False)
        self.assertEqual(payload["metadata"]["operating_system"], "Linux")
        self.assertEqual(
            payload["metadata"]["investigation_hints"],
            ["host_health", "process_inventory"],
        )

        serialized = json.dumps(payload, sort_keys=True)
        self.assertNotIn(sensitive_subject, serialized)
        self.assertNotIn("/usr/bin/python3", serialized)
        self.assertNotIn("action_proposals", serialized)
        self.assertNotIn('"target"', serialized)
        self.assertEqual(
            payload["evidence"]["subject_hmac_sha256"],
            identity.identify_scoped(sensitive_subject, "response-subject-v1"),
        )
        self.assertEqual(
            payload["evidence"]["correlation_signal_codes"],
            ["cross_signal_actor_bonus", "process_network_corroboration"],
        )

    def test_handoff_event_id_and_subject_identity_are_deterministic(self) -> None:
        report, event, _ = _fixture()
        identity = PrivacyIdentity(b"k" * 32)
        first = build_response_handoff_events(report, [event], privacy_identity=identity)[0]
        second = build_response_handoff_events(report, [event], privacy_identity=identity)[0]
        self.assertEqual(first["event_id"], second["event_id"])
        self.assertEqual(
            first["evidence"]["subject_hmac_sha256"],
            second["evidence"]["subject_hmac_sha256"],
        )

    def test_handoff_fails_closed_if_quietward_claims_executable_authority(self) -> None:
        report, event, _ = _fixture(executable=True)
        with self.assertRaisesRegex(ValueError, "executable QuietWard proposals"):
            build_response_handoff_events(
                report,
                [event],
                privacy_identity=PrivacyIdentity(b"k" * 32),
            )

    def test_handoff_rejects_response_incompatible_host_ids(self) -> None:
        report, event, _ = _fixture(host_id="host id with spaces")
        with self.assertRaisesRegex(ValueError, "host_id"):
            build_response_handoff_events(
                report,
                [event],
                privacy_identity=PrivacyIdentity(b"k" * 32),
            )


if __name__ == "__main__":
    unittest.main()
