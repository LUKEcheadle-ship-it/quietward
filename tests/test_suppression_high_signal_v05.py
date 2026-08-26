from __future__ import annotations

from datetime import datetime, timezone
from quietward.collectors.models import CollectionBatch, CollectorSnapshot
from quietward.config import SentinelConfig
from quietward.contracts import AnalysisReport, EventKind, SecurityEvent
from quietward.service import QuietWardService
from quietward.storage import PersistResult


NOW = datetime(2026, 8, 23, 20, 0, tzinfo=timezone.utc)


class _Collector:
    host_id = "host-test"

    def __init__(self, event: SecurityEvent) -> None:
        self.event = event

    def collect(self, previous=None):
        return CollectionBatch(
            CollectorSnapshot(observed_at=NOW, host_id=self.host_id),
            (self.event,),
        )


class _Store:
    def __init__(self) -> None:
        self.suppression_inputs: list[SecurityEvent] = []

    def latest_snapshot(self):
        return None

    def verify_evidence_chain(self):
        return {"cycles_checked": 0, "valid": True}

    def filter_suppressed_events(self, events, *, now=None):
        values = list(events)
        self.suppression_inputs.extend(values)
        return [], values

    def persist_cycle(self, batch, report, *, started_at, completed_at):
        self.persisted_batch = batch
        return PersistResult(1, 0, 0, 1, 1, "a" * 64, None)

    def set_integrity_manifest(self, manifest):
        raise AssertionError("no integrity manifest expected")

    def scanner_last_run(self, scanner):
        return None

    def summary(self):
        return {
            "schema_version": 4,
            "actions_executed": 0,
            "evidence_chain": {"valid": True, "cycles_checked": 0},
        }


class _Pipeline:
    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    def analyze(self, events):
        self.events = list(events)
        return AnalysisReport(
            generated_at=NOW,
            mode="observe_only",
            events_analyzed=len(self.events),
            assessments=(),
            findings=(),
            action_proposals=(),
            actions_executed=0,
        )


class _Alerts:
    def emit_pending(self, store):
        return 0


class _Scanners:
    def run(self, job):
        raise AssertionError("no scanner jobs expected")


def _service(event: SecurityEvent, tmp_path):
    store = _Store()
    pipeline = _Pipeline()
    config = SentinelConfig.from_dict(
        {
            "state_dir": str(tmp_path.resolve()),
            "collector": {
                "include_processes": False,
                "include_listening_sockets": False,
                "include_outbound_connections": False,
                "include_auth_journal": False,
                "include_docker": False,
                "include_persistence": False,
                "sensitive_files": [],
            },
            "dashboard": {"enabled": False},
            "self_integrity": {"enabled": False},
        }
    )
    service = QuietWardService(
        config,
        collector=_Collector(event),
        pipeline=pipeline,
        store=store,
        scanner_executor=_Scanners(),
        alert_sink=_Alerts(),
        clock=lambda: NOW,
    )
    return service, store, pipeline


def test_reverse_shell_process_bypasses_subject_suppression(tmp_path) -> None:
    event = SecurityEvent(
        "event-high",
        NOW,
        "host-test",
        "windows_process_snapshot",
        EventKind.PROCESS_START,
        "powershell.exe",
        {"suspicious_markers": ["reverse_shell"]},
        0.95,
    )
    service, store, pipeline = _service(event, tmp_path)
    result = service.run_cycle()

    assert store.suppression_inputs == []
    assert pipeline.events == [event]
    assert result.suppressed_events == 0


def test_credential_spray_bypasses_subject_suppression(tmp_path) -> None:
    event = SecurityEvent(
        "event-spray",
        NOW,
        "host-test",
        "journald_ssh_read_only",
        EventKind.AUTH_FAILURE,
        "auth:pseudonym:user-pseudonym",
        {
            "credential_spray_candidate": True,
            "suspicious_markers": ["credential_spray"],
        },
        0.98,
    )
    service, store, pipeline = _service(event, tmp_path)
    result = service.run_cycle()

    assert store.suppression_inputs == []
    assert pipeline.events == [event]
    assert result.suppressed_events == 0


def test_low_signal_process_can_still_be_suppressed(tmp_path) -> None:
    event = SecurityEvent(
        "event-low",
        NOW,
        "host-test",
        "windows_process_snapshot",
        EventKind.PROCESS_START,
        "powershell.exe",
        {"suspicious_markers": ["encoded_command"]},
        0.7,
    )
    service, store, pipeline = _service(event, tmp_path)
    result = service.run_cycle()

    assert store.suppression_inputs == [event]
    assert pipeline.events == []
    assert result.suppressed_events == 1
