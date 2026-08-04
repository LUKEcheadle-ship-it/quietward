from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from quietward.collectors.models import CollectionBatch, CollectorSnapshot, ProcessRecord, SocketRecord
from quietward.contracts import EventKind, SecurityEvent
from quietward.qualification import QualificationConfig, TargetHostQualifier


class FakeCollector:
    def __init__(self, batches: list[CollectionBatch]) -> None:
        self.batches = batches
        self.index = 0
        self.previous_seen: list[CollectorSnapshot | None] = []

    def collect(self, previous: CollectorSnapshot | None = None) -> CollectionBatch:
        self.previous_seen.append(previous)
        batch = self.batches[self.index]
        self.index += 1
        return batch


class Timer:
    def __init__(self, values: list[float]) -> None:
        self.values = iter(values)

    def __call__(self) -> float:
        return next(self.values)


class QualificationTests(unittest.TestCase):
    def test_baseline_change_kinds_are_defined_by_the_event_contract(self) -> None:
        self.assertTrue(TargetHostQualifier.BASELINE_CHANGE_KINDS <= set(EventKind))

    def setUp(self) -> None:
        now = datetime(2026, 7, 30, 18, 0, tzinfo=timezone.utc)
        self.snapshot1 = CollectorSnapshot(
            observed_at=now,
            host_id="host-test",
            processes=(ProcessRecord(1, 0, "root", "init", "init", "hash"),),
            sockets=(SocketRecord("tcp", "127.0.0.1", 22, "sshd"),),
        )
        self.snapshot2 = CollectorSnapshot(
            observed_at=now + timedelta(seconds=1),
            host_id="host-test",
            processes=self.snapshot1.processes,
            sockets=self.snapshot1.sockets,
        )

    def qualifier(self, batches, *, max_cycle_ms=5000, max_peak_rss_bytes=512 * 1024 * 1024, rss=10_000_000):
        return TargetHostQualifier(
            FakeCollector(batches),
            QualificationConfig(cycles=2, interval_seconds=0, max_cycle_ms=max_cycle_ms, max_peak_rss_bytes=max_peak_rss_bytes),
            timer=Timer([0.0, 0.01, 1.0, 1.02]),
            sleeper=lambda _: None,
            rss_reader=lambda: rss,
        ).run()

    def test_clean_qualification_passes_and_executes_nothing(self) -> None:
        collector = FakeCollector([CollectionBatch(self.snapshot1, ()), CollectionBatch(self.snapshot2, ())])
        report = TargetHostQualifier(
            collector,
            QualificationConfig(cycles=2, interval_seconds=0, max_cycle_ms=100),
            timer=Timer([0.0, 0.01, 1.0, 1.02]),
            sleeper=lambda _: None,
            rss_reader=lambda: 10_000_000,
        ).run()
        self.assertEqual(report.decision, "PASS")
        self.assertEqual(report.blockers, ())
        self.assertEqual(sum(c.actions_executed for c in report.cycles), 0)
        self.assertIs(collector.previous_seen[0], None)
        self.assertEqual(collector.previous_seen[1], self.snapshot1)
        self.assertFalse(report.to_dict()["safety"]["host_modified"])

    def test_duration_limit_failure_is_explicit(self) -> None:
        report = self.qualifier([CollectionBatch(self.snapshot1, ()), CollectionBatch(self.snapshot2, ())], max_cycle_ms=5, rss=None)
        self.assertEqual(report.decision, "FAIL")
        self.assertTrue(any("duration" in blocker for blocker in report.blockers))

    def test_peak_rss_limit_failure_is_explicit(self) -> None:
        report = self.qualifier([CollectionBatch(self.snapshot1, ()), CollectionBatch(self.snapshot2, ())], max_peak_rss_bytes=1_000, rss=2_000)
        self.assertEqual(report.decision, "FAIL")
        self.assertTrue(any("peak RSS" in blocker for blocker in report.blockers))

    def test_first_cycle_change_event_fails_baseline_gate(self) -> None:
        event = SecurityEvent("event-1", self.snapshot1.observed_at, "host-test", "debian_socket_snapshot", EventKind.NEW_LISTENING_PORT, "tcp://0.0.0.0:9999", {"raw_arguments_persisted": False})
        report = self.qualifier([CollectionBatch(self.snapshot1, (event,)), CollectionBatch(self.snapshot2, ())], rss=None)
        self.assertEqual(report.decision, "FAIL")
        self.assertTrue(any("baseline emitted" in blocker for blocker in report.blockers))

    def test_privacy_flag_violation_fails(self) -> None:
        event = SecurityEvent("event-2", self.snapshot2.observed_at, "host-test", "journald_ssh_read_only", EventKind.AUTH_FAILURE, "auth:test", {"raw_log_message_persisted": True})
        report = self.qualifier([CollectionBatch(self.snapshot1, ()), CollectionBatch(self.snapshot2, (event,))], rss=None)
        self.assertEqual(report.decision, "FAIL")
        self.assertTrue(any("privacy flag" in blocker for blocker in report.blockers))

    def test_optional_collector_error_is_warning(self) -> None:
        snapshot1 = CollectorSnapshot(self.snapshot1.observed_at, "host-test", errors=("optional Docker inventory unavailable: permission denied",))
        snapshot2 = CollectorSnapshot(self.snapshot2.observed_at, "host-test", errors=("optional Docker inventory unavailable: permission denied",))
        report = self.qualifier([CollectionBatch(snapshot1, ()), CollectionBatch(snapshot2, ())], rss=None)
        self.assertEqual(report.decision, "PASS")
        self.assertTrue(report.warnings)


if __name__ == "__main__":
    unittest.main()
