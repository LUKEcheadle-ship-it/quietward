from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from quietward.alerts import LocalAlertSink
from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import SentinelConfig
from quietward.service import SentinelService, _atomic_json
from quietward.storage import SentinelStore

class FakeCollector:
    host_id = "host-test"
    def __init__(self, snapshot: CollectorSnapshot) -> None: self.snapshot = snapshot
    def collect(self, previous=None) -> CollectionBatch: return CollectionBatch(self.snapshot, ())

class ServiceHealthRecoveryTests(unittest.TestCase):
    def config(self, root: Path) -> SentinelConfig:
        return SentinelConfig.from_dict({"state_dir": str(root), "collector": {"include_processes": False, "include_listening_sockets": False, "include_outbound_connections": False, "include_auth_journal": False, "include_docker": False, "include_persistence": False, "sensitive_files": []}, "dashboard": {"enabled": False}, "self_integrity": {"enabled": False}})
    def service(self, root: Path):
        config = self.config(root); now = datetime(2026, 8, 7, 22, 30, tzinfo=timezone.utc); snapshot = CollectorSnapshot(observed_at=now, host_id="host-test", collector_version="windows-read-only-v1"); store = SentinelStore(config.storage)
        service = SentinelService(config, collector=FakeCollector(snapshot), store=store, alert_sink=LocalAlertSink(config.storage.alert_log_path), clock=lambda: now)
        return config, store, service
    def test_atomic_json_completes_short_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "health.json"; real_write = os.write
            def short_write(descriptor: int, data: object) -> int: return real_write(descriptor, bytes(data[:2]))
            with patch("quietward.service.os.write", side_effect=short_write): _atomic_json(path, {"status": "healthy", "actions_executed": 0})
            loaded = json.loads(path.read_text(encoding="utf-8")); self.assertEqual(loaded["status"], "healthy"); self.assertEqual(loaded["actions_executed"], 0)
    def test_atomic_json_cleans_temporary_file_on_replace_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / "health.json"
            with patch("quietward.service.os.replace", side_effect=OSError("replace failed")):
                with self.assertRaisesRegex(OSError, "replace failed"): _atomic_json(path, {"status": "healthy"})
            self.assertFalse(path.exists()); self.assertEqual(list(root.glob(".health.json.tmp-*")), [])
    def test_cycle_survives_rich_health_summary_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config, store, service = self.service(Path(temporary))
            try:
                with patch.object(service, "_write_health", side_effect=OSError("summary failed")): result = service.run_cycle()
                self.assertEqual(result.persist.cycle_id, 1); self.assertEqual(store.summary()["cycles"], 1); health = json.loads(config.service.health_path.read_text(encoding="utf-8")); self.assertEqual(health["status"], "healthy"); self.assertEqual(health["error"], "health summary unavailable"); self.assertEqual(health["safety"]["actions_executed"], 0)
            finally: store.close()
    def test_successful_cycle_resets_failure_count_before_health_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config, store, service = self.service(Path(temporary))
            try:
                service.consecutive_failures = 3; service.run_cycle(); health = json.loads(config.service.health_path.read_text(encoding="utf-8")); self.assertEqual(service.consecutive_failures, 0); self.assertEqual(health["consecutive_failures"], 0)
            finally: store.close()

if __name__ == "__main__": unittest.main()
