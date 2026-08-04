from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from quietward.collectors.command import CommandResult, ReadOnlyCommandRunner
from quietward.collectors.windows import (
    WindowsCollectorConfig,
    WindowsReadOnlyCollector,
)
from quietward.collectors.windows_commands import WINDOWS_PROCESS_COMMAND
from quietward.collectors.windows_parsers import (
    parse_windows_auth_events,
    parse_windows_connections,
    parse_windows_defender,
    parse_windows_persistence,
    parse_windows_processes,
    parse_windows_sockets,
)
from quietward.contracts import ActionProposal, ActionType, EventKind
from quietward.platforms import (
    PlatformFamily,
    default_state_dir,
    detect_platform,
    validate_collector_choice,
)
from quietward.privacy_identity import PrivacyIdentity
from quietward.remediation import plan_from_proposal


class FakeRunner:
    def __init__(self, values: dict[tuple[str, ...], str]) -> None:
        self.values = values
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv):
        normalized = tuple(argv)
        self.calls.append(normalized)
        return CommandResult(normalized, 0, self.values.get(normalized, "[]"), "")


class CrossPlatformFoundationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = PrivacyIdentity(b"k" * 32)

    def test_platform_detection_and_selection(self) -> None:
        windows = detect_platform(system_name="Windows", release="11")
        self.assertEqual(windows.family, PlatformFamily.WINDOWS)
        self.assertEqual(validate_collector_choice("auto", windows), "windows")
        with tempfile.TemporaryDirectory() as temporary:
            os_release = Path(temporary) / "os-release"
            os_release.write_text('ID="ubuntu"\nID_LIKE="debian"\n', encoding="utf-8")
            linux = detect_platform(
                system_name="Linux",
                release="6.8",
                os_release_path=os_release,
                systemd_path=Path(temporary) / "missing-systemd",
            )
        self.assertEqual(linux.family, PlatformFamily.LINUX)
        self.assertEqual(linux.distro_id, "ubuntu")
        self.assertEqual(validate_collector_choice("auto", linux), "linux")

    def test_default_state_directories_use_quietward_branding(self) -> None:
        windows = detect_platform(system_name="Windows", release="11")
        with patch.dict(
            os.environ,
            {"LOCALAPPDATA": r"C:\Users\test-user\AppData\Local"},
        ):
            self.assertEqual(
                default_state_dir(windows),
                Path(r"C:\Users\test-user\AppData\Local") / "QuietWard" / "state",
            )
        linux = detect_platform(system_name="Linux", release="6.1")
        self.assertTrue(
            default_state_dir(linux).as_posix().endswith("/.local/state/quietward")
        )

    def test_windows_commands_are_exact_allowlisted_tuples(self) -> None:
        normalized = ReadOnlyCommandRunner.validate(
            WINDOWS_PROCESS_COMMAND,
            (WINDOWS_PROCESS_COMMAND,),
        )
        self.assertEqual(normalized, WINDOWS_PROCESS_COMMAND)
        with self.assertRaisesRegex(ValueError, "allowlist"):
            ReadOnlyCommandRunner.validate(
                ("powershell.exe", "-Command", "Remove-Item C:\\*"),
                (WINDOWS_PROCESS_COMMAND,),
            )
        with self.assertRaisesRegex(ValueError, "shell"):
            ReadOnlyCommandRunner.validate(("cmd.exe", "/c", "whoami"))

    def test_windows_processes_redact_identity_and_command_line(self) -> None:
        raw = json.dumps(
            [{
                "ProcessId": 100,
                "ParentProcessId": 4,
                "Name": "powershell.exe",
                "ExecutablePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -EncodedCommand SECRET-COMMAND",
                "UserName": "MACHINE\\Administrator",
            }]
        )
        records = parse_windows_processes(raw, self.identity)
        serialized = json.dumps([record.to_dict() for record in records])
        self.assertNotIn("Administrator", serialized)
        self.assertNotIn("SECRET-COMMAND", serialized)
        self.assertIn("user_identity_hash", serialized)
        self.assertIn("encoded_command", serialized)

    def test_defender_status_is_labeled_external_evidence(self) -> None:
        status = parse_windows_defender(
            json.dumps({
                "AntivirusEnabled": True,
                "RealTimeProtectionEnabled": True,
                "AntivirusSignatureVersion": "1.2.3",
                "AntivirusSignatureAge": 1,
                "ActiveThreatCount": 0,
                "RemediationRequired": False,
            })
        )
        self.assertIsNotNone(status)
        value = status.to_dict()
        self.assertEqual(value["source"], "microsoft_defender")
        self.assertFalse(value["quietward_malware_verdict"])

    def test_windows_network_records_redact_addresses(self) -> None:
        sockets = parse_windows_sockets(json.dumps([
            {"Protocol": "tcp", "LocalAddress": "0.0.0.0", "LocalPort": 445, "ProcessName": "smbd-equivalent"},
            {"Protocol": "tcp", "LocalAddress": "::", "LocalPort": 445, "ProcessName": "smbd-equivalent"},
        ]))
        self.assertEqual(len(sockets), 1)
        self.assertEqual(sockets[0].local_address, "*")
        connections = parse_windows_connections(
            json.dumps([{"Protocol": "tcp", "RemoteAddress": "203.0.113.5", "RemotePort": 443, "ProcessName": "browser"}]),
            self.identity,
        )
        serialized = json.dumps([record.to_dict() for record in connections])
        self.assertNotIn("203.0.113.5", serialized)
        self.assertIn("remote_address_hash", serialized)

    def test_windows_persistence_redacts_name_command_and_account(self) -> None:
        raw = json.dumps([{
            "Category": "service_auto",
            "Name": "PrivateServiceName",
            "Command": "C:\\Users\\private-user\\AppData\\Local\\service.exe",
            "State": "Running",
            "Account": "MACHINE\\private-user",
        }])
        records = parse_windows_persistence(raw, self.identity)
        serialized = json.dumps([record.to_dict() for record in records])
        self.assertNotIn("PrivateServiceName", serialized)
        self.assertNotIn("private-user", serialized)
        self.assertNotIn("service.exe", serialized)
        self.assertIn("account_identity_hash", serialized)
        self.assertIn("user_writable_target", serialized)

    def test_windows_auth_events_redact_username_and_source(self) -> None:
        raw = json.dumps([{
            "TimeCreated": "2026-08-01T17:00:00Z",
            "User": "Administrator",
            "SourceAddress": "198.51.100.8",
        }])
        events = parse_windows_auth_events(
            raw,
            host_id="host-test",
            privacy_identity=self.identity,
            fallback_time=datetime.now(timezone.utc),
        )
        serialized = json.dumps([event.to_dict() for event in events])
        self.assertNotIn("Administrator", serialized)
        self.assertNotIn("198.51.100.8", serialized)
        self.assertIn("user_identity_hash", serialized)
        self.assertIn("source_address_hash", serialized)

    def test_windows_collector_baselines_then_emits_windows_source(self) -> None:
        initial = json.dumps([{
            "Category": "scheduled_task",
            "Name": "ExistingTask",
            "Command": "",
            "State": "Ready",
            "Account": "",
        }])
        changed = json.dumps([
            {"Category": "scheduled_task", "Name": "ExistingTask", "Command": "", "State": "Ready", "Account": ""},
            {"Category": "registry_run", "Name": "NewEntry", "Command": "C:\\Program Files\\Example\\example.exe", "State": "enabled", "Account": ""},
        ])
        from quietward.collectors.windows_commands import WINDOWS_PERSISTENCE_COMMAND

        first_runner = FakeRunner({WINDOWS_PERSISTENCE_COMMAND: initial})
        config = WindowsCollectorConfig(
            include_processes=False,
            include_sockets=False,
            include_connections=False,
            include_auth_events=False,
            include_docker=False,
            include_persistence=True,
        )
        first = WindowsReadOnlyCollector(config, runner=first_runner, host_id="host-test")
        first.privacy_identity = self.identity
        baseline = first.collect()
        self.assertEqual(baseline.events, ())

        second_runner = FakeRunner({WINDOWS_PERSISTENCE_COMMAND: changed})
        second = WindowsReadOnlyCollector(config, runner=second_runner, host_id="host-test")
        second.privacy_identity = self.identity
        result = second.collect(baseline.snapshot)
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].kind, EventKind.PERSISTENCE_CHANGE)
        self.assertTrue(result.events[0].source.startswith("windows_"))

    def test_remediation_plans_remain_review_only(self) -> None:
        proposal = ActionProposal(
            proposal_id="proposal-1",
            finding_id="finding-1",
            action_type=ActionType.STOP_PROCESS,
            target="process-hash",
            reason="test",
            destructive=True,
            requires_approval=True,
            executable_in_current_mode=False,
        )
        plan = plan_from_proposal(proposal, platform="windows")
        self.assertTrue(plan.requires_explicit_approval)
        self.assertFalse(plan.executable_in_current_mode)
        self.assertEqual(plan.to_dict()["actions_executed"], 0)
        with self.assertRaisesRegex(ValueError, "not executable"):
            type(plan)(
                plan_id=plan.plan_id,
                finding_id=plan.finding_id,
                platform=plan.platform,
                title=plan.title,
                risk=plan.risk,
                steps=plan.steps,
                rollback=plan.rollback,
                requires_explicit_approval=True,
                executable_in_current_mode=True,
            )


if __name__ == "__main__":
    unittest.main()
