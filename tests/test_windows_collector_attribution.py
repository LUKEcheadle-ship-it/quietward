from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from quietward.collectors.command import CommandResult
from quietward.collectors.models import CollectorSnapshot
from quietward.collectors.windows import WindowsCollectorConfig, WindowsReadOnlyCollector
from quietward.collectors.windows_commands import WINDOWS_DEFENDER_COMMAND, WINDOWS_PROCESS_COMMAND, WINDOWS_SOCKET_COMMAND
from quietward.contracts import EventKind

class FakeRunner:
    def __init__(self, outputs): self.outputs = outputs; self.calls = []
    def run(self, argv):
        key = tuple(argv); self.calls.append(key); value = self.outputs.get(key)
        if value is None: return CommandResult(key, 127, "", "not configured")
        return CommandResult(key, 0, value, "")

class WindowsCollectorAttributionTests(unittest.TestCase):
    def test_new_listener_is_enriched_from_same_cycle_process_inventory(self) -> None:
        process_output = json.dumps({"ProcessId": 4242, "ParentProcessId": 4000, "Name": "example.exe", "ExecutablePath": "C:\\Users\\user\\AppData\\Local\\Temp\\example.exe", "CommandLine": "example.exe --serve", "UserName": "MACHINE\\user"})
        socket_output = json.dumps({"Protocol": "tcp", "LocalAddress": "0.0.0.0", "LocalPort": 4444, "OwningProcess": 4242, "ProcessName": "example"})
        defender_output = json.dumps({"AntivirusEnabled": True, "RealTimeProtectionEnabled": True, "ActiveThreatCount": 0, "RemediationRequired": False})
        runner = FakeRunner({WINDOWS_DEFENDER_COMMAND: defender_output, WINDOWS_PROCESS_COMMAND: process_output, WINDOWS_SOCKET_COMMAND: socket_output})
        collector = WindowsReadOnlyCollector(WindowsCollectorConfig(include_processes=True, include_sockets=True, include_connections=False, include_auth_events=False, include_docker=False, include_persistence=False, privacy_identity_key_path=None), runner=runner, host_id="host-test")
        previous = CollectorSnapshot(observed_at=datetime(2026, 8, 7, 20, 0, tzinfo=timezone.utc), host_id="host-test", collector_version="windows-read-only-v1")
        batch = collector.collect(previous); listeners = [event for event in batch.events if event.kind == EventKind.NEW_LISTENING_PORT]; self.assertEqual(len(listeners), 1); event = listeners[0]
        self.assertEqual(event.source, "windows_socket_snapshot"); self.assertEqual(event.attributes["owner_pid"], 4242); self.assertEqual(event.attributes["owner_executable"], "example.exe"); self.assertEqual(event.attributes["process_attribution"], "pid_inventory_match"); self.assertIn("user_writable_executable", event.attributes["owner_suspicious_markers"]); self.assertFalse(event.attributes["raw_command_line_persisted"]); self.assertFalse(event.attributes["raw_username_persisted"]); self.assertGreaterEqual(event.confidence, 0.9); self.assertIn(WINDOWS_PROCESS_COMMAND, runner.calls); self.assertIn(WINDOWS_SOCKET_COMMAND, runner.calls)
    def test_listener_attribution_degrades_safely_when_process_inventory_fails(self) -> None:
        socket_output = json.dumps({"Protocol": "tcp", "LocalAddress": "127.0.0.1", "LocalPort": 8765, "OwningProcess": 9999, "ProcessName": "unknown-app"}); runner = FakeRunner({WINDOWS_SOCKET_COMMAND: socket_output})
        collector = WindowsReadOnlyCollector(WindowsCollectorConfig(include_processes=True, include_sockets=True, include_connections=False, include_auth_events=False, include_docker=False, include_persistence=False), runner=runner, host_id="host-test")
        previous = CollectorSnapshot(observed_at=datetime(2026, 8, 7, 20, 0, tzinfo=timezone.utc), host_id="host-test", collector_version="windows-read-only-v1")
        batch = collector.collect(previous); listeners = [event for event in batch.events if event.kind == EventKind.NEW_LISTENING_PORT]; self.assertEqual(len(listeners), 1); event = listeners[0]; self.assertEqual(event.attributes["owner_pid"], 9999); self.assertIsNone(event.attributes["owner_executable"]); self.assertEqual(event.attributes["process_attribution"], "socket_pid_only"); self.assertTrue(any("process inventory unavailable" in error for error in batch.snapshot.errors))
if __name__ == "__main__": unittest.main()
