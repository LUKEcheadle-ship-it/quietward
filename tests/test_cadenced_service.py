from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quietward.alerts import LocalAlertSink
from quietward.cadence import CadenceController
from quietward.cadenced_service import CadencedPerformanceSentinelService
from quietward.collectors.diff import diff_snapshots
from quietward.collectors.models import CollectionBatch, CollectorSnapshot, ContainerRecord, FileRecord, PersistenceRecord, ProcessRecord, SocketRecord
from quietward.config import SentinelConfig
from quietward.storage import SentinelStore


@dataclass(frozen=True, slots=True)
class FakeConfig:
    sensitive_files: tuple[Path, ...]
    include_processes: bool = True
    include_sockets: bool = True
    include_connections: bool = False
    include_auth_journal: bool = False
    include_docker: bool = True
    include_persistence: bool = True

class FakeCollector:
    host_id = "host-a"
    def __init__(self, monitored_file: Path) -> None:
        self.config = FakeConfig((monitored_file,))
        self.calls: list[FakeConfig] = []
    def collect(self, previous=None) -> CollectionBatch:
        self.calls.append(self.config)
        now = datetime.now(timezone.utc)
        snapshot = CollectorSnapshot(
            observed_at=now, host_id=self.host_id,
            processes=(ProcessRecord(10, 1, "u", "proc", "proc", "args"),) if self.config.include_processes else (),
            sockets=(SocketRecord("tcp", "127.0.0.1", 9000, "proc"),) if self.config.include_sockets else (),
            containers=(ContainerRecord("cid", "image:v1", "app", "Up"),) if self.config.include_docker else (),
            files=(FileRecord(str(self.config.sensitive_files[0]), True, "regular", 0o600, 1, 1, "abc"),) if self.config.sensitive_files else (),
            persistence=(PersistenceRecord("service", "svc", "fingerprint"),) if self.config.include_persistence else (),
            collector_version="fake-read-only-v1",
        )
        return CollectionBatch(snapshot, tuple(diff_snapshots(snapshot, previous)))

class CadencedServiceTests(unittest.TestCase):
    def test_fast_cycle_preserves_not_due_domains_without_false_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            monitored_file = (root / "sensitive.txt").resolve(); monitored_file.write_text("x", encoding="utf-8")
            config = SentinelConfig.from_dict({
                "state_dir": str(root.resolve()),
                "collector": {"include_processes": True, "include_listening_sockets": True, "include_outbound_connections": False, "include_auth_journal": False, "include_docker": True, "include_persistence": True, "sensitive_files": [str(monitored_file)]},
                "dashboard": {"enabled": False}, "self_integrity": {"enabled": False},
            })
            monotonic = [0.0]; wall = [datetime(2026, 8, 8, 1, 0, tzinfo=timezone.utc)]
            cadence = CadenceController(fast_seconds=60.0, standard_seconds=300.0, deep_seconds=900.0, maintenance_seconds=300.0, monotonic=lambda: monotonic[0])
            collector = FakeCollector(monitored_file)
            with SentinelStore(config.storage) as store:
                service = CadencedPerformanceSentinelService(config, collector=collector, store=store, cadence_controller=cadence, alert_sink=LocalAlertSink(config.storage.alert_log_path), clock=lambda: wall[0])
                first = service.run_cycle()
                self.assertEqual(set(first.coverage["cadence"]["due_lanes"]), {"fast", "standard", "deep", "maintenance"})
                self.assertTrue(first.coverage["resolution_safe"]); self.assertTrue(first.coverage["baseline"]["ready"]); self.assertEqual(first.coverage["baseline"]["confidence"], "initial")
                monotonic[0] = 60.0; wall[0] += timedelta(minutes=1)
                second = service.run_cycle(); states = {item["name"]: item["state"] for item in second.coverage["domains"]}
                self.assertEqual(second.coverage["cadence"]["due_lanes"], ["fast"]); self.assertEqual(states["persistence"], "not_due"); self.assertEqual(states["docker"], "not_due"); self.assertEqual(states["sensitive_files"], "not_due")
                self.assertTrue(second.coverage["operationally_healthy"]); self.assertFalse(second.coverage["resolution_safe"]); self.assertTrue(second.coverage["baseline"]["ready"]); self.assertFalse(second.coverage["baseline"]["established"]); self.assertEqual(second.findings, 0)
                latest = store.latest_snapshot(); self.assertIsNotNone(latest); self.assertEqual(len(latest.persistence), 1); self.assertEqual(len(latest.containers), 1); self.assertEqual(len(latest.files), 1)
                self.assertFalse(collector.calls[-1].include_persistence); self.assertFalse(collector.calls[-1].include_docker); self.assertEqual(collector.calls[-1].sensitive_files, ())
                performance = service.runtime_metrics.summary(); self.assertEqual(performance["samples"], 2); self.assertIn("collector", performance["phases_ms"]); self.assertIn("persistence", performance["phases_ms"]); self.assertIn("baseline", performance["phases_ms"]); self.assertIn("health", performance["latest_ms"]); self.assertEqual(performance["latest_context"]["due_lanes"], ["fast"]); self.assertEqual(performance["latest_context"]["baseline_confidence"], "initial")
                health = json.loads(config.service.health_path.read_text(encoding="utf-8")); self.assertEqual(health["performance"]["samples"], 2); self.assertEqual(health["coverage"]["baseline"]["confidence"], "initial"); self.assertEqual(health["cadence"]["actions_executed"], 0)


if __name__ == "__main__": unittest.main()
