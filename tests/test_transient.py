from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from quietward.collectors.transient import TransientRecord, transient_events
from quietward.contracts import EventKind


def _record(sequence: int, *, parent: int = 42, encoded: bool = False) -> TransientRecord:
    return TransientRecord(
        sequence,
        datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=sequence),
        "process_start",
        {
            "pid": 1000 + sequence,
            "ppid": parent,
            "uid": 1001,
            "process_name": "bash" if encoded else "true",
            "observation_stage": "exec" if encoded else "fork",
            "encoded_shell_chain": encoded,
            "args_hash": "a" * 64 if encoded else None,
        },
    )


def test_short_lived_fork_burst_creates_one_bounded_finding() -> None:
    events = transient_events([_record(index) for index in range(1, 9)], "host-test")
    assert [item.kind for item in events] == [EventKind.PROCESS_BURST]
    assert events[0].attributes["process_count"] == 8
    assert events[0].attributes["parent_child_count"] == 8
    assert events[0].attributes["raw_arguments_persisted"] is False


def test_small_fork_set_is_not_a_burst() -> None:
    assert transient_events([_record(index) for index in range(1, 4)], "host-test") == []


def test_encoded_exec_is_normalized_without_raw_arguments() -> None:
    events = transient_events([_record(1, encoded=True)], "host-test")
    assert [item.kind for item in events] == [EventKind.ENCODED_COMMAND]
    assert events[0].attributes["encoded_shell_chain"] is True
    assert "argv" not in events[0].attributes
    assert events[0].attributes["raw_arguments_persisted"] is False


def test_raw_argument_fields_are_rejected_at_boundary() -> None:
    with pytest.raises(ValueError, match="raw command"):
        TransientRecord.from_dict(
            {
                "schema_version": "1.0",
                "sequence": 1,
                "observed_at": "2026-01-01T00:00:00Z",
                "event_type": "process_start",
                "data": {"argv": ["secret"]},
            }
        )


def test_file_scan_beacon_and_auth_bursts_are_bounded() -> None:
    when = datetime(2026, 1, 1, tzinfo=timezone.utc)
    records = [
        TransientRecord(index + 1, when + timedelta(milliseconds=index), "file_activity", {"operation": "write"})
        for index in range(40)
    ]
    records.extend(
        TransientRecord(100 + index, when + timedelta(seconds=index), "network_flow", {"source_address_hash": "source", "destination_hash": "dest", "destination_port": port})
        for index, port in enumerate((8001, 8002, 8003, 8004))
    )
    records.extend(
        TransientRecord(200 + index, when + timedelta(seconds=10 + index), "network_flow", {"source_address_hash": "source", "destination_hash": "dest", "destination_port": 22})
        for index in range(3)
    )
    records.extend(
        TransientRecord(300 + index, when + timedelta(seconds=20 + index), "auth_failure", {"source_address_hash": "source", "user_identity_hash": "user", "service": "ssh"})
        for index in range(3)
    )
    kinds = {item.kind for item in transient_events(records, "host-test")}
    assert {EventKind.SUSPICIOUS_FILE_CHURN, EventKind.PORT_SCAN, EventKind.BEACON, EventKind.AUTH_FAILURE} <= kinds
