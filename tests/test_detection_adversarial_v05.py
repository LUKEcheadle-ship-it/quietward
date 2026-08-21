from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from quietward.collectors.windows_parsers import parse_windows_processes
from quietward.contracts import EventKind, SecurityEvent, Severity
from quietward.correlation import IncidentCorrelator
from quietward.scoring import DeterministicRiskScorer


NOW = datetime(2026, 8, 21, 19, 0, tzinfo=timezone.utc)


class _Privacy:
    def identify_scoped(self, value: str, scope: str) -> str:
        import hashlib

        return hashlib.sha256((scope + ":" + value).encode()).hexdigest()[:32]


def _windows_process(name: str, command_line: str, *, pid: int = 500, ppid: int = 100):
    rows = [
        {
            "ProcessId": pid,
            "ParentProcessId": ppid,
            "Name": name,
            "ExecutablePath": rf"C:\Windows\System32\{name}",
            "CommandLine": command_line,
            "UserName": r"HOST\User",
        }
    ]
    return parse_windows_processes(json.dumps(rows), _Privacy())[0]


def _event(
    event_id: str,
    kind: EventKind,
    subject: str,
    *,
    seconds: int = 0,
    markers: list[str] | None = None,
    attributes: dict | None = None,
    confidence: float = 0.95,
) -> SecurityEvent:
    value = dict(attributes or {})
    if markers is not None:
        value["suspicious_markers"] = markers
    return SecurityEvent(
        event_id=event_id,
        observed_at=NOW + timedelta(seconds=seconds),
        host_id="host-adversarial-v05",
        source="adversarial-regression",
        kind=kind,
        subject=subject,
        attributes=value,
        confidence=confidence,
    )


def _score(event: SecurityEvent):
    return DeterministicRiskScorer().score(event)


def test_high_signal_behaviors_cannot_silently_drop_below_high() -> None:
    cases = (
        ("reverse_shell", EventKind.PROCESS_START),
        ("credential_dumping", EventKind.PROCESS_START),
        ("document_spawned_interpreter", EventKind.PROCESS_START),
        ("web_server_spawned_suspicious_shell", EventKind.PROCESS_START),
        ("ransomware_recovery_inhibition", EventKind.PROCESS_START),
        ("event_log_clearing", EventKind.PROCESS_START),
        ("docker_socket_mount", EventKind.CONTAINER_CONFIGURATION_CHANGE),
        ("host_root_mount", EventKind.CONTAINER_CONFIGURATION_CHANGE),
    )
    for index, (marker, kind) in enumerate(cases):
        result = _score(
            _event(
                f"evt-high-{index}",
                kind,
                f"subject:{marker}",
                markers=[marker],
                attributes={"baseline_deviation": 1.0},
            )
        )
        assert result.severity in {Severity.HIGH, Severity.CRITICAL}, (marker, result)
        assert any("high_confidence_behavior_floor=65.0" in reason for reason in result.reasons)


def test_lower_specificity_admin_or_location_markers_do_not_get_high_floor_alone() -> None:
    for index, marker in enumerate(
        (
            "defender_tamper_command",
            "user_writable_executable",
            "network_listener_tool",
            "no_new_privileges_missing",
            "unhealthy_container",
        )
    ):
        result = _score(
            _event(
                f"evt-context-{index}",
                EventKind.PROCESS_START,
                f"subject:{marker}",
                markers=[marker],
                attributes={},
            )
        )
        assert result.severity not in {Severity.HIGH, Severity.CRITICAL}, (marker, result)
        assert not any("high_confidence_behavior_floor" in reason for reason in result.reasons)


def test_common_admin_read_commands_do_not_gain_impact_evasion_markers() -> None:
    benign = (
        ("vssadmin.exe", "vssadmin.exe list shadows"),
        ("wevtutil.exe", "wevtutil.exe qe Security /c:20"),
        ("powershell.exe", "powershell.exe Get-MpComputerStatus"),
        ("wbadmin.exe", "wbadmin.exe get versions"),
    )
    blocked = {
        "ransomware_recovery_inhibition",
        "event_log_clearing",
        "defender_tamper_command",
    }
    for name, command in benign:
        record = _windows_process(name, command)
        assert blocked.isdisjoint(record.suspicious_markers), (command, record.suspicious_markers)


def test_explicit_impact_evasion_commands_are_detected_without_raw_command_persistence() -> None:
    cases = (
        ("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", "ransomware_recovery_inhibition"),
        ("wmic.exe", "wmic.exe shadowcopy delete", "ransomware_recovery_inhibition"),
        ("wevtutil.exe", "wevtutil.exe cl Security", "event_log_clearing"),
        (
            "powershell.exe",
            "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
            "defender_tamper_command",
        ),
    )
    for name, command, expected in cases:
        record = _windows_process(name, command)
        assert expected in record.suspicious_markers
        serialized = record.to_dict()
        assert command not in str(serialized)
        assert "args_hash" in serialized


def test_large_multi_account_spray_remains_high_while_small_single_account_failure_does_not() -> None:
    spray = _score(
        _event(
            "evt-spray",
            EventKind.AUTH_FAILURE,
            "auth:source:user",
            markers=["credential_spray"],
            attributes={
                "failed_count": 2,
                "source_failed_count": 64,
                "distinct_accounts": 12,
            },
            confidence=0.98,
        )
    )
    assert spray.severity in {Severity.HIGH, Severity.CRITICAL}
    assert any("credential_spray_high_priority_floor=65.0" in reason for reason in spray.reasons)

    normal = _score(
        _event(
            "evt-normal-auth",
            EventKind.AUTH_FAILURE,
            "auth:source:user",
            attributes={"failed_count": 3, "source_failed_count": 3, "distinct_accounts": 1},
            confidence=0.8,
        )
    )
    assert normal.severity not in {Severity.HIGH, Severity.CRITICAL}


def test_high_signal_two_phase_chain_requires_cross_subject_and_time_bound() -> None:
    scorer = DeterministicRiskScorer()
    events = [
        _event(
            "evt-shell",
            EventKind.PROCESS_START,
            "proc:shell",
            markers=["reverse_shell"],
        ),
        _event(
            "evt-persist",
            EventKind.PERSISTENCE_CHANGE,
            "task:persist",
            seconds=120,
            attributes={"persistence_indicator": True},
        ),
    ]
    findings = IncidentCorrelator().correlate(events, [scorer.score(item) for item in events])
    chains = [item for item in findings if item.finding_id.startswith("qwf-chain-")]
    assert len(chains) == 1

    late = [events[0], _event(
        "evt-persist-late",
        EventKind.PERSISTENCE_CHANGE,
        "task:persist",
        seconds=16 * 60,
        attributes={"persistence_indicator": True},
    )]
    late_findings = IncidentCorrelator().correlate(late, [scorer.score(item) for item in late])
    assert not any(item.finding_id.startswith("qwf-chain-") for item in late_findings)

    same_subject = [
        _event(
            "evt-shell-same",
            EventKind.PROCESS_START,
            "same",
            markers=["reverse_shell"],
        ),
        _event(
            "evt-persist-same",
            EventKind.PERSISTENCE_CHANGE,
            "same",
            seconds=120,
            attributes={"persistence_indicator": True},
        ),
    ]
    same_findings = IncidentCorrelator().correlate(
        same_subject,
        [scorer.score(item) for item in same_subject],
    )
    assert not any(item.finding_id.startswith("qwf-chain-") for item in same_findings)
