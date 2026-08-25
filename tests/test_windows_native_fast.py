from __future__ import annotations

import json
import os
import unittest
from datetime import datetime, timezone

from quietward.collectors.command import CommandResult
from quietward.collectors.models import CollectorSnapshot, ProcessRecord, SocketRecord
from quietward.collectors.windows import WindowsCollectorConfig, WindowsReadOnlyCollector
from quietward.collectors.windows_commands import WINDOWS_PROCESS_COMMAND
from quietward.collectors.windows_native_fast import (
    WindowsNativeFastInventory,
    collect_windows_native_fast,
)


NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)


class RejectingRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv):
        command = tuple(argv)
        self.calls.append(command)
        raise AssertionError(f"quiet native FAST cycle must not execute {command!r}")


class DetailRunner:
    def __init__(self, payload: str) -> None:
        self.payload = payload
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv):
        command = tuple(argv)
        self.calls.append(command)
        if command != WINDOWS_PROCESS_COMMAND:
            raise AssertionError(f"unexpected command: {command!r}")
        return CommandResult(command, 0, self.payload, "")


def inventory(
    processes: tuple[ProcessRecord, ...],
    sockets: tuple[SocketRecord, ...] = (),
) -> WindowsNativeFastInventory:
    rows = [
        {
            "Protocol": item.protocol,
            "LocalAddress": item.local_address,
            "LocalPort": item.port,
            "OwningProcess": 0,
            "ProcessName": item.process_name,
        }
        for item in sockets
    ]
    return WindowsNativeFastInventory(
        processes=processes,
        sockets=sockets,
        listener_attribution={},
        socket_output=json.dumps(rows, separators=(",", ":")),
        processes_ok=True,
        sockets_ok=True,
        errors=(),
    )


class WindowsNativeFastTests(unittest.TestCase):
    def config(self, *, include_sockets: bool = True) -> WindowsCollectorConfig:
        return WindowsCollectorConfig(
            include_processes=True,
            include_sockets=include_sockets,
            include_connections=False,
            include_auth_events=False,
            include_docker=False,
            include_persistence=False,
            sensitive_files=(),
            refresh_slow_context=False,
        )

    def test_stable_quiet_fast_cycle_executes_no_external_command(self) -> None:
        prior_process = ProcessRecord(
            100,
            4,
            "a" * 32,
            "ordinary.exe",
            "ordinary.exe",
            "b" * 32,
        )
        socket = SocketRecord("tcp", "loopback", 8765, "ordinary")
        previous = CollectorSnapshot(
            observed_at=NOW,
            host_id="host-test",
            processes=(prior_process,),
            sockets=(socket,),
            collector_version="windows-read-only-v1",
        )
        native_process = ProcessRecord(
            100,
            4,
            "unavailable",
            "ordinary.exe",
            "ordinary.exe",
            "unavailable",
        )
        runner = RejectingRunner()
        collector = WindowsReadOnlyCollector(
            self.config(),
            runner=runner,
            host_id="host-test",
            native_fast_collector=lambda: inventory((native_process,), (socket,)),
        )
        batch = collector.collect(previous)
        self.assertEqual(runner.calls, [])
        self.assertEqual(batch.snapshot.processes[0].user, prior_process.user)
        self.assertEqual(batch.snapshot.processes[0].args_hash, prior_process.args_hash)
        self.assertEqual(batch.events, ())

    def test_new_high_risk_process_requests_one_detail_inventory(self) -> None:
        prior = ProcessRecord(
            100,
            4,
            "a" * 32,
            "ordinary.exe",
            "ordinary.exe",
            "b" * 32,
        )
        previous = CollectorSnapshot(
            observed_at=NOW,
            host_id="host-test",
            processes=(prior,),
            collector_version="windows-read-only-v1",
        )
        native_values = (
            ProcessRecord(100, 4, "unavailable", "ordinary.exe", "ordinary.exe", "unavailable"),
            ProcessRecord(200, 100, "unavailable", "powershell.exe", "powershell.exe", "unavailable"),
        )
        detail = json.dumps(
            [
                {
                    "ProcessId": 100,
                    "ParentProcessId": 4,
                    "Name": "ordinary.exe",
                    "ExecutablePath": r"C:\\Program Files\\Example\\ordinary.exe",
                    "CommandLine": "ordinary.exe",
                    "UserName": "TEST\\user",
                },
                {
                    "ProcessId": 200,
                    "ParentProcessId": 100,
                    "Name": "powershell.exe",
                    "ExecutablePath": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -EncodedCommand AAAA",
                    "UserName": "TEST\\user",
                },
            ]
        )
        runner = DetailRunner(detail)
        collector = WindowsReadOnlyCollector(
            self.config(include_sockets=False),
            runner=runner,
            host_id="host-test",
            native_fast_collector=lambda: inventory(native_values),
        )
        batch = collector.collect(previous)
        self.assertEqual(runner.calls, [WINDOWS_PROCESS_COMMAND])
        powershell = next(item for item in batch.snapshot.processes if item.pid == 200)
        self.assertIn("encoded_command", powershell.suspicious_markers)

    @unittest.skipUnless(os.name == "nt", "requires native Windows APIs")
    def test_native_windows_inventory_observes_current_process_and_listeners(self) -> None:
        value = collect_windows_native_fast()
        self.assertTrue(value.processes_ok, value.errors)
        self.assertTrue(value.sockets_ok, value.errors)
        self.assertTrue(any(item.pid == os.getpid() for item in value.processes))
        self.assertIsInstance(value.sockets, tuple)


if __name__ == "__main__":
    unittest.main()
