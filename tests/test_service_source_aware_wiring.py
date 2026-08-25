from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from quietward.alerts import LocalAlertSink
from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import SentinelConfig
from quietward.service import SentinelService
from quietward.source_aware_lifecycle import SourceAwareIncidentLifecycleRepository
from quietward.storage import SentinelStore


class FakeCollector:
    host_id = "host-test"
    def __init__(self, snapshot: CollectorSnapshot) -> None: self.snapshot = snapshot
    def collect(self, previous=None) -> CollectionBatch: return CollectionBatch(self.snapshot, ())

class FakeSummary:
    def __init__(self, coverage_complete: bool) -> None: self.coverage_complete = coverage_complete
    def to_dict(self):
        return {"cycle_id": 1, "new": 0, "recurring": 0, "changed": 0, "resolved": 0, "active_total": 0, "coverage_complete": self.coverage_complete, "already_processed": False, "actions_executed": 0}

class CapturingLifecycle:
    def __init__(self) -> None: self.domains = None; self.coverage_complete = None
    def catch_up_from_evidence_chain(self, **_kwargs): return 0
    def reconcile_cycle(self, _cycle_id, _findings, _events, *, observed_at, coverage_complete, coverage_domains):
        self.domains = [dict(item) for item in coverage_domains]; self.coverage_complete = coverage_complete; return FakeSummary(coverage_complete)
    def summary(self): return {"active": 0, "actions_executed": 0}

class ServiceSourceAwareWiringTests(unittest.TestCase):
    def config(self, root: Path) -> SentinelConfig:
        return SentinelConfig.from_dict({"state_dir": str(root), "collector": {"type": "windows", "include_processes": True, "include_listening_sockets": True, "include_outbound_connections": False, "include_auth_journal": False, "include_docker": False, "include_persistence": False, "sensitive_files": []}, "dashboard": {"enabled": False}, "self_integrity": {"enabled": False}})

    def test_real_store_defaults_to_source_aware_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self.config(Path(temporary)); store = SentinelStore(config.storage)
            try:
                snapshot = CollectorSnapshot(observed_at=datetime.now(timezone.utc), host_id="host-test", collector_version="windows-read-only-v1")
                service = SentinelService(config, collector=FakeCollector(snapshot), store=store, alert_sink=LocalAlertSink(config.storage.alert_log_path))
                self.assertIsInstance(service.lifecycle_repository, SourceAwareIncidentLifecycleRepository)
            finally: store.close()

    def test_service_passes_structured_domains_to_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); config = self.config(root); now = datetime(2026, 8, 7, 23, 30, tzinfo=timezone.utc)
            snapshot = CollectorSnapshot(observed_at=now, host_id="host-test", collector_version="windows-read-only-v1"); store = SentinelStore(config.storage); lifecycle = CapturingLifecycle()
            try:
                service = SentinelService(config, collector=FakeCollector(snapshot), store=store, lifecycle_repository=lifecycle, alert_sink=LocalAlertSink(config.storage.alert_log_path), clock=lambda: now); result = service.run_cycle()
            finally: store.close()
        self.assertIsNotNone(lifecycle.domains); states = {item["name"]: item["state"] for item in lifecycle.domains}; self.assertEqual(states["processes"], "complete"); self.assertEqual(states["listening_sockets"], "complete"); self.assertFalse(states.get("outbound_connections") == "complete"); self.assertEqual(lifecycle.coverage_complete, result.coverage["resolution_safe"]); self.assertEqual(result.actions_executed if hasattr(result, "actions_executed") else 0, 0)

if __name__ == "__main__": unittest.main()
