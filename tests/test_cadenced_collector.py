from __future__ import annotations

import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from quietward.cadenced_collector import CadencedCollectorAdapter
from quietward.collectors.diff import diff_snapshots
from quietward.collectors.models import CollectionBatch, CollectorSnapshot, ContainerRecord, FileRecord, PersistenceRecord, ProcessRecord, SocketRecord
from quietward.contracts import EventKind, SecurityEvent


@dataclass(frozen=True, slots=True)
class FakeConfig:
    sensitive_files: tuple[Path, ...] = (Path("/tmp/example"),)
    include_processes: bool = True
    include_sockets: bool = True
    include_connections: bool = False
    include_auth_journal: bool = False
    include_docker: bool = True
    include_persistence: bool = True

@dataclass(frozen=True, slots=True)
class FakeWindowsConfig:
    sensitive_files: tuple[Path, ...] = ()
    include_processes: bool = True
    include_sockets: bool = True
    include_connections: bool = False
    include_auth_events: bool = False
    include_docker: bool = False
    include_persistence: bool = True
    refresh_slow_context: bool = True

@dataclass(frozen=True, slots=True)
class FakeAuthConfig:
    sensitive_files: tuple[Path, ...] = ()
    include_processes: bool = False
    include_sockets: bool = False
    include_connections: bool = False
    include_auth_journal: bool = True
    include_docker: bool = False
    include_persistence: bool = False

class FakeCollector:
    host_id = "host-a"
    def __init__(self) -> None:
        self.config = FakeConfig()
        self.calls: list[FakeConfig] = []
    def collect(self, previous: CollectorSnapshot | None = None) -> CollectionBatch:
        self.calls.append(self.config)
        now = datetime(2026, 8, 8, 0, 1, tzinfo=timezone.utc)
        snapshot = CollectorSnapshot(
            observed_at=now, host_id=self.host_id,
            processes=(ProcessRecord(10, 1, "u", "proc", "proc", "args"),) if self.config.include_processes else (),
            sockets=(SocketRecord("tcp", "127.0.0.1", 9000, "proc"),) if self.config.include_sockets else (),
            containers=(ContainerRecord("cid", "image:v1", "app", "Up"),) if self.config.include_docker else (),
            files=(FileRecord("/tmp/example", True, "regular", 0o600, 1, 1, "abc"),) if self.config.sensitive_files else (),
            persistence=(PersistenceRecord("service", "svc", "new-fingerprint"),) if self.config.include_persistence else (),
            collector_version="fake-read-only-v1",
        )
        return CollectionBatch(snapshot, tuple(diff_snapshots(snapshot, previous)))

class FakeWindowsCollector:
    host_id = "host-windows"
    def __init__(self) -> None:
        self.config = FakeWindowsConfig()
        self.runner = None

class FakeAuthCollector:
    host_id = "host-auth"
    def __init__(self, event_ids: list[str]) -> None:
        self.config = FakeAuthConfig()
        self.event_ids = list(event_ids)
        self.index = 0
    def collect(self, previous=None) -> CollectionBatch:
        now = datetime(2026, 8, 8, 0, 2, tzinfo=timezone.utc)
        snapshot = CollectorSnapshot(observed_at=now, host_id=self.host_id, collector_version="fake-auth-read-only-v1")
        if not self.config.include_auth_journal:
            return CollectionBatch(snapshot, ())
        event_id = self.event_ids[self.index]
        self.index += 1
        event = SecurityEvent(event_id, now, self.host_id, "journald_ssh_read_only", EventKind.AUTH_FAILURE, "auth:source:user", {"failed_count": 1})
        return CollectionBatch(snapshot, (event,))

class CadencedCollectorTests(unittest.TestCase):
    def previous(self) -> CollectorSnapshot:
        return CollectorSnapshot(
            observed_at=datetime(2026, 8, 8, 0, 0, tzinfo=timezone.utc), host_id="host-a",
            processes=(ProcessRecord(10, 1, "u", "proc", "proc", "args"),),
            sockets=(SocketRecord("tcp", "127.0.0.1", 9000, "proc"),),
            containers=(ContainerRecord("cid", "image:v1", "app", "Up"),),
            files=(FileRecord("/tmp/example", True, "regular", 0o600, 1, 1, "abc"),),
            persistence=(PersistenceRecord("service", "svc", "old-fingerprint"),), collector_version="fake-read-only-v1")

    def test_fast_lane_preserves_skipped_standard_and_deep_state(self) -> None:
        raw = FakeCollector(); adapter = CadencedCollectorAdapter(raw); adapter.set_active_domains({"processes", "listening_sockets"}); previous = self.previous(); batch = adapter.collect(previous)
        self.assertEqual(batch.snapshot.persistence, previous.persistence)
        self.assertEqual(batch.snapshot.containers, previous.containers)
        self.assertEqual(batch.snapshot.files, previous.files)
        self.assertFalse(raw.calls[-1].include_persistence); self.assertFalse(raw.calls[-1].include_docker); self.assertEqual(raw.calls[-1].sensitive_files, ()); self.assertEqual(raw.config, FakeConfig())
        self.assertFalse(any(event.subject == "svc" for event in batch.events))

    def test_standard_lane_can_observe_persistence_change(self) -> None:
        raw = FakeCollector(); adapter = CadencedCollectorAdapter(raw); adapter.set_active_domains({"persistence"}); batch = adapter.collect(self.previous())
        self.assertEqual(batch.snapshot.persistence[0].fingerprint, "new-fingerprint"); self.assertTrue(any(event.subject == "svc" for event in batch.events))

    def test_windows_fast_domains_no_longer_force_persistence_or_slow_context(self) -> None:
        adapter = CadencedCollectorAdapter(FakeWindowsCollector()); active = adapter.set_active_domains({"processes", "listening_sockets"})
        self.assertEqual(active, frozenset({"processes", "listening_sockets"}))
        config = adapter._cadenced_config(); self.assertTrue(config.include_processes); self.assertTrue(config.include_sockets); self.assertFalse(config.include_persistence); self.assertFalse(config.refresh_slow_context)

    def test_windows_standard_lane_refreshes_slow_context_even_if_optional_domains_disabled(self) -> None:
        raw = FakeWindowsCollector(); raw.config = FakeWindowsConfig(include_persistence=False, include_docker=False); adapter = CadencedCollectorAdapter(raw); adapter.set_active_domains({"persistence", "docker"}); config = adapter._cadenced_config()
        self.assertFalse(config.include_persistence); self.assertFalse(config.include_docker); self.assertTrue(config.refresh_slow_context)

    def test_rolling_auth_event_ids_are_bounded_and_deduplicated(self) -> None:
        raw = FakeAuthCollector(["a", "a", "b", "c", "a"]); adapter = CadencedCollectorAdapter(raw, max_recent_auth_event_ids=2); adapter.set_active_domains({"authentication"})
        first = adapter.collect(); repeated = adapter.collect(); second = adapter.collect(); third = adapter.collect(); evicted_then_seen_again = adapter.collect()
        self.assertEqual([item.event_id for item in first.events], ["a"]); self.assertEqual(repeated.events, ()); self.assertEqual([item.event_id for item in second.events], ["b"]); self.assertEqual([item.event_id for item in third.events], ["c"]); self.assertEqual([item.event_id for item in evicted_then_seen_again.events], ["a"])


if __name__ == "__main__": unittest.main()
