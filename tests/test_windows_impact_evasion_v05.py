from __future__ import annotations

import json
from datetime import datetime, timezone

from quietward.collectors.windows_parsers import parse_windows_processes
from quietward.contracts import EventKind, SecurityEvent, Severity
from quietward.scoring import DeterministicRiskScorer


class _FakePrivacyIdentity:
    def identify_scoped(self, value: str, scope: str) -> str:
        return (scope.replace("-", "") + value.replace("\\", ""))[:32].ljust(32, "0")


def _process(command: str, name: str = "cmd.exe"):
    rows = [
        {
            "ProcessId": 500,
            "ParentProcessId": 100,
            "Name": name,
            "ExecutablePath": rf"C:\Windows\System32\{name}",
            "CommandLine": command,
            "UserName": r"HOST\User",
        }
    ]
    return parse_windows_processes(json.dumps(rows), _FakePrivacyIdentity())[0]


def _score(markers: tuple[str, ...]):
    return DeterministicRiskScorer().score(
        SecurityEvent(
            event_id="evt-impact",
            observed_at=datetime.now(timezone.utc),
            host_id="host-a",
            source="windows_process_snapshot",
            kind=EventKind.PROCESS_START,
            subject="process",
            attributes={
                "suspicious_markers": list(markers),
                "baseline_deviation": 1.0,
            },
            confidence=0.9,
        )
    )


def test_vssadmin_shadow_deletion_is_high_priority_recovery_inhibition() -> None:
    record = _process("vssadmin.exe delete shadows /all /quiet", "vssadmin.exe")
    assert "ransomware_recovery_inhibition" in record.suspicious_markers
    assessment = _score(record.suspicious_markers)
    assert assessment.severity in {Severity.HIGH, Severity.CRITICAL}
    assert any("ransomware_recovery_inhibition" in reason for reason in assessment.reasons)


def test_shadowcopy_and_backup_catalog_deletion_are_marked() -> None:
    assert "ransomware_recovery_inhibition" in _process(
        "wmic.exe shadowcopy delete", "wmic.exe"
    ).suspicious_markers
    assert "ransomware_recovery_inhibition" in _process(
        "wbadmin.exe delete catalog -quiet", "wbadmin.exe"
    ).suspicious_markers


def test_vssadmin_listing_is_not_recovery_inhibition() -> None:
    record = _process("vssadmin.exe list shadows", "vssadmin.exe")
    assert "ransomware_recovery_inhibition" not in record.suspicious_markers


def test_explicit_event_log_clear_is_high_priority() -> None:
    record = _process("wevtutil.exe cl Security", "wevtutil.exe")
    assert "event_log_clearing" in record.suspicious_markers
    assert _score(record.suspicious_markers).severity in {Severity.HIGH, Severity.CRITICAL}


def test_event_log_query_is_not_clear_marker() -> None:
    record = _process("wevtutil.exe qe Security /c:10", "wevtutil.exe")
    assert "event_log_clearing" not in record.suspicious_markers


def test_defender_disable_command_is_context_marker_not_forced_high_by_itself() -> None:
    record = _process(
        "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
        "powershell.exe",
    )
    assert "defender_tamper_command" in record.suspicious_markers
    # The marker is intentionally not in the high-confidence floor set because
    # legitimate administrators can change Defender preferences.
    assessment = _score(("defender_tamper_command",))
    assert assessment.severity in {Severity.MEDIUM, Severity.HIGH}
    assert not any("high_confidence_behavior_floor" in reason for reason in assessment.reasons)


def test_normal_defender_status_command_is_not_tamper_marker() -> None:
    record = _process("powershell.exe Get-MpComputerStatus", "powershell.exe")
    assert "defender_tamper_command" not in record.suspicious_markers
