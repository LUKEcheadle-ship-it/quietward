from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from quietward.alerts import LocalAlertSink
from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import SentinelConfig
from quietward.service import SentinelService
from quietward.storage import SentinelStore

class FakeCollector:
    host_id = "host-test"
    def __init__(self, snapshot: CollectorSnapshot) -> None: self.snapshot = snapshot
    def collect(self, previous=None) -> CollectionBatch: return CollectionBatch(self.snapshot, ())

class ServiceCoverageTests(unittest.TestCase):
    def config(self, root: Path) -> SentinelConfig:
        return SentinelConfig.from_dict({"state_dir": str(root), "collector": {"type": "windows", "include_processes": True, "include_listening_sockets": True, "include_outbound_connections": False, "include_auth_journal": False, "include_docker": False, "include_persistence": False, "sensitive_files": []}, "dashboard": {"enabled": False}, "self_integrity": {"enabled": False}})
    def run_snapshot(self, errors=()):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup); root = Path(temporary.name); config = self.config(root); now = datetime(2026, 8, 7, 22, 0, tzinfo=timezone.utc)
        snapshot = CollectorSnapshot(observed_at=now, host_id="host-test", errors=tuple(errors), collector_version="windows-read-only-v1")
        store = SentinelStore(config.storage); self.addCleanup(store.close)
        service = SentinelService(config, collector=FakeCollector(snapshot), store=store, alert_sink=LocalAlertSink(config.storage.alert_log_path), clock=lambda: now)
        return config, store, service.run_cycle()
    def test_complete_core_coverage_is_resolution_safe(self) -> None:
        config, store, result = self.run_snapshot(); self.assertTrue(result.coverage["resolution_safe"]); self.assertEqual(result.coverage["cycle_id"], 1); self.assertTrue(result.coverage["metadata_persisted"]); self.assertEqual(result.coverage["actions_executed"], 0)
        states = {item["name"]: item["state"] for item in result.coverage["domains"]}; self.assertEqual(states["processes"], "complete"); self.assertEqual(states["listening_sockets"], "complete"); self.assertEqual(states["self_integrity"], "disabled"); self.assertEqual(states["microsoft_defender"], "complete"); self.assertTrue(result.lifecycle["coverage_complete"])
        stored = json.loads(store.get_metadata("last_coverage_report") or "{}"); self.assertEqual(stored["cycle_id"], 1); self.assertTrue(stored["resolution_safe"]); self.assertTrue(stored["metadata_persisted"]); self.assertEqual(stored["actions_executed"], 0)
        health = json.loads(config.service.health_path.read_text(encoding="utf-8")); self.assertTrue(health["coverage"]["resolution_safe"]); self.assertEqual(health["coverage"]["cycle_id"], 1); self.assertEqual(health["safety"]["actions_executed"], 0)
    def test_required_process_coverage_failure_blocks_resolution(self) -> None:
        _, store, result = self.run_snapshot(("Windows process inventory unavailable: exit code 5",)); self.assertFalse(result.coverage["resolution_safe"]); process = next(item for item in result.coverage["domains"] if item["name"] == "processes"); self.assertEqual(process["state"], "degraded"); self.assertEqual(process["issue_count"], 1); self.assertFalse(result.lifecycle["coverage_complete"]); stored = json.loads(store.get_metadata("last_coverage_report") or "{}"); self.assertFalse(stored["resolution_safe"])
    def test_optional_defender_failure_does_not_block_resolution(self) -> None:
        _, _, result = self.run_snapshot(("optional Microsoft Defender status unavailable: exit code 1",)); self.assertTrue(result.coverage["resolution_safe"]); defender = next(item for item in result.coverage["domains"] if item["name"] == "microsoft_defender"); self.assertEqual(defender["state"], "degraded"); self.assertFalse(defender["required_for_resolution"]); self.assertTrue(result.lifecycle["coverage_complete"])
    def test_unclassified_collector_warning_fails_closed(self) -> None:
        _, _, result = self.run_snapshot(("unexpected warning detail",)); self.assertFalse(result.coverage["resolution_safe"]); other = next(item for item in result.coverage["domains"] if item["name"] == "collector_other"); self.assertEqual(other["state"], "degraded"); self.assertTrue(other["required_for_resolution"])

if __name__ == "__main__": unittest.main()
