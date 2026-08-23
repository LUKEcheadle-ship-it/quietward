from __future__ import annotations

from datetime import datetime, timedelta, timezone

from quietward.collectors.diff import diff_snapshots
from quietward.collectors.models import CollectorSnapshot, ProcessRecord
from quietward.contracts import EventKind, Severity
from quietward.scoring import DeterministicRiskScorer


NOW = datetime(2026, 8, 23, 18, 0, tzinfo=timezone.utc)


def _snapshot(processes: tuple[ProcessRecord, ...], *, seconds: int) -> CollectorSnapshot:
    return CollectorSnapshot(
        observed_at=NOW + timedelta(seconds=seconds),
        host_id="host-linux-parent-child",
        processes=processes,
    )


def _proc(
    pid: int,
    ppid: int,
    name: str,
    *,
    markers: tuple[str, ...] = (),
    args_hash: str | None = None,
) -> ProcessRecord:
    return ProcessRecord(
        pid=pid,
        ppid=ppid,
        user="unavailable",
        command_name=name,
        executable=name,
        args_hash=args_hash or f"hash-{pid}-{name}",
        suspicious_markers=markers,
        privileged_context=False,
    )


def test_web_server_spawned_reverse_shell_gets_explicit_high_signal_marker() -> None:
    parent = _proc(100, 1, "nginx")
    child = _proc(101, 100, "bash", markers=("reverse_shell",))
    previous = _snapshot((parent,), seconds=0)
    current = _snapshot((parent, child), seconds=5)

    events = diff_snapshots(current, previous)
    process_events = [item for item in events if item.kind is EventKind.PROCESS_START]
    assert len(process_events) == 1
    event = process_events[0]
    assert "server_spawned_suspicious_shell" in event.attributes["suspicious_markers"]
    assert event.attributes["parent_command_name"] == "nginx"
    assert event.attributes["raw_arguments_persisted"] is False

    assessment = DeterministicRiskScorer().score(event)
    assert assessment.severity in {Severity.HIGH, Severity.CRITICAL}
    assert any("server_spawned_suspicious_shell" in reason for reason in assessment.reasons)


def test_server_parent_without_existing_suspicious_child_marker_does_not_create_event() -> None:
    parent = _proc(200, 1, "apache2")
    child = _proc(201, 200, "bash")
    previous = _snapshot((parent,), seconds=0)
    current = _snapshot((parent, child), seconds=5)

    events = diff_snapshots(current, previous)
    assert not any(item.kind is EventKind.PROCESS_START for item in events)


def test_suspicious_shell_from_non_server_parent_keeps_original_marker_only() -> None:
    parent = _proc(300, 1, "sshd")
    child = _proc(301, 300, "bash", markers=("encoded_shell_chain",))
    previous = _snapshot((parent,), seconds=0)
    current = _snapshot((parent, child), seconds=5)

    events = diff_snapshots(current, previous)
    process_events = [item for item in events if item.kind is EventKind.PROCESS_START]
    assert len(process_events) == 1
    markers = process_events[0].attributes["suspicious_markers"]
    assert "encoded_shell_chain" in markers
    assert "server_spawned_suspicious_shell" not in markers


def test_non_shell_child_from_server_parent_does_not_gain_server_shell_marker() -> None:
    parent = _proc(400, 1, "gunicorn")
    child = _proc(401, 400, "python", markers=("network_payload_retrieval",))
    previous = _snapshot((parent,), seconds=0)
    current = _snapshot((parent, child), seconds=5)

    events = diff_snapshots(current, previous)
    process_events = [item for item in events if item.kind is EventKind.PROCESS_START]
    assert len(process_events) == 1
    assert "server_spawned_suspicious_shell" not in process_events[0].attributes["suspicious_markers"]
