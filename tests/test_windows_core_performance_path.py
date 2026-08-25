from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from quietward.collectors.command import CommandResult
from quietward.collectors.models import CollectorSnapshot, DefenderStatus
from quietward.collectors.windows import WindowsCollectorConfig, WindowsReadOnlyCollector
from quietward.collectors.windows_commands import (
    WINDOWS_CORE_COMMAND,
    WINDOWS_PROCESS_COMMAND,
)
from quietward.collectors.windows_fast_core_command import (
    WINDOWS_FAST_CORE_COMMAND,
)
from quietward.collectors.windows_native_fast import WindowsNativeFastInventory
from quietward.privacy_identity import PrivacyIdentity


class FakeRunner:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def run(self, argv):
        command = tuple(argv)
        self.calls.append(command)
        if command not in self.responses:
            raise AssertionError(f"unexpected command: {command!r}")
        return self.responses[command]


def result(command, payload, returncode=0):
    return CommandResult(tuple(command), returncode, payload, "")


def native_unavailable() -> WindowsNativeFastInventory:
    return WindowsNativeFastInventory(
        processes=(),
        sockets=(),
        listener_attribution={},
        socket_output="[]",
        processes_ok=False,
        sockets_ok=False,
        errors=("synthetic native path unavailable",),
    )


def core_payload(
    *,
    processes_ok=True,
    persistence_ok=True,
    defender_ok=True,
    include_user=True,
):
    return json.dumps(
        {
            "DefenderOk": defender_ok,
            "Defender": (
                {
                    "AntivirusEnabled": True,
                    "RealTimeProtectionEnabled": True,
                    "AntivirusSignatureAge": 0,
                    "ActiveThreatCount": 0,
                    "RemediationRequired": False,
                }
                if defender_ok
                else None
            ),
            "ProcessesOk": processes_ok,
            "Processes": [
                {
                    "ProcessId": 1234,
                    "ParentProcessId": 1,
                    "Name": "app.exe",
                    "ExecutablePath": "C:\\Program Files\\App\\app.exe",
                    "CommandLine": "app.exe --serve",
                    "UserName": "TEST\\user" if include_user else "",
                }
            ],
            "SocketsOk": True,
            "Sockets": [
                {
                    "Protocol": "tcp",
                    "LocalAddress": "127.0.0.1",
                    "LocalPort": 8765,
                    "OwningProcess": 1234,
                    "ProcessName": "app",
                }
            ],
            "PersistenceOk": persistence_ok,
            "Persistence": [],
        }
    )


class WindowsCorePerformancePathTests(unittest.TestCase):
    def make_collector(
        self,
        runner,
        *,
        include_persistence=True,
        refresh_slow_context=True,
        native_fast_collector=native_unavailable,
    ):
        collector = WindowsReadOnlyCollector(
            WindowsCollectorConfig(
                include_processes=True,
                include_sockets=True,
                include_connections=False,
                include_auth_events=False,
                include_docker=False,
                include_persistence=include_persistence,
                sensitive_files=(),
                refresh_slow_context=refresh_slow_context,
            ),
            runner=runner,
            host_id="host-test",
            native_fast_collector=native_fast_collector,
        )
        collector.privacy_identity = PrivacyIdentity(b"p" * 32)
        return collector

    def test_fast_core_fallback_uses_one_command_and_preserves_last_defender_context(self) -> None:
        runner = FakeRunner(
            {
                WINDOWS_FAST_CORE_COMMAND: result(
                    WINDOWS_FAST_CORE_COMMAND,
                    core_payload(
                        persistence_ok=False,
                        defender_ok=False,
                        include_user=False,
                    ),
                )
            }
        )
        previous_defender = DefenderStatus(
            antivirus_enabled=True,
            real_time_protection_enabled=True,
            signature_version="1.2.3",
            signature_age_days=0,
            active_threat_count=0,
            remediation_required=False,
        )
        previous = CollectorSnapshot(
            observed_at=datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc),
            host_id="host-test",
            defender=previous_defender,
            collector_version="windows-read-only-v1",
        )
        batch = self.make_collector(
            runner,
            include_persistence=False,
            refresh_slow_context=False,
        ).collect(previous)
        self.assertEqual(runner.calls, [WINDOWS_FAST_CORE_COMMAND])
        self.assertEqual(len(batch.snapshot.processes), 1)
        self.assertEqual(len(batch.snapshot.sockets), 1)
        self.assertEqual(batch.snapshot.persistence, ())
        self.assertEqual(batch.snapshot.defender, previous_defender)
        self.assertEqual(batch.snapshot.errors, ())

    def test_full_core_domains_use_one_powershell_when_persistence_is_due(self) -> None:
        runner = FakeRunner(
            {WINDOWS_CORE_COMMAND: result(WINDOWS_CORE_COMMAND, core_payload())}
        )
        batch = self.make_collector(runner, include_persistence=True).collect()
        self.assertEqual(runner.calls, [WINDOWS_CORE_COMMAND])
        self.assertEqual(len(batch.snapshot.processes), 1)
        self.assertEqual(len(batch.snapshot.sockets), 1)
        self.assertIsNotNone(batch.snapshot.defender)
        self.assertEqual(batch.snapshot.errors, ())

    def test_only_failed_process_domain_falls_back_to_process_command(self) -> None:
        process_payload = json.dumps(
            [
                {
                    "ProcessId": 1234,
                    "ParentProcessId": 1,
                    "Name": "app.exe",
                    "ExecutablePath": "C:\\Program Files\\App\\app.exe",
                    "CommandLine": "app.exe --serve",
                    "UserName": "TEST\\user",
                }
            ]
        )
        runner = FakeRunner(
            {
                WINDOWS_CORE_COMMAND: result(
                    WINDOWS_CORE_COMMAND,
                    core_payload(processes_ok=False),
                ),
                WINDOWS_PROCESS_COMMAND: result(
                    WINDOWS_PROCESS_COMMAND,
                    process_payload,
                ),
            }
        )
        batch = self.make_collector(runner).collect()
        self.assertEqual(
            runner.calls,
            [WINDOWS_CORE_COMMAND, WINDOWS_PROCESS_COMMAND],
        )
        self.assertEqual(len(batch.snapshot.processes), 1)
        self.assertEqual(len(batch.snapshot.sockets), 1)
        self.assertEqual(batch.snapshot.errors, ())


if __name__ == "__main__":
    unittest.main()
