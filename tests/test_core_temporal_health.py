from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from quietward.cadence import CadenceController
from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import SentinelConfig
from quietward.contracts import EventKind, SecurityEvent
from quietward.core_service import CoreSentinelService
from quietward.core_store import CoreSentinelStore


@dataclass(frozen=True, slots=True)
class FakeConfig:
    sensitive_files: tuple[Path, ...] = ()
    include_processes: bool = True
    include_sockets: bool = True
    include_connections: bool = False
    include_auth_journal: bool = False
    include_docker: bool = False
    include_persistence: bool = False

class EventCollector:
    host_id = "host-context"
    def __init__(self, observed_at: datetime) -> None:
        self.config = FakeConfig(); self.observed_at = observed_at
    def collect(self, previous=None) -> CollectionBatch:
        event = SecurityEvent("listener-context-1", self.observed_at, self.host_id, "windows_socket_snapshot", EventKind.NEW_LISTENING_PORT, "tcp://0.0.0.0:4555", {"owner_pid": 4555, "owner_command_name": "context-agent.exe", "external_bind": True})
        snapshot = CollectorSnapshot(observed_at=self.observed_at, host_id=self.host_id, collector_version="fake-read-only-v1")
        return CollectionBatch(snapshot, (event,))

class CoreTemporalHealthTests(unittest.TestCase):
    def test_successful_cycle_commits_context_before_healthy_health_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); now = datetime(2026, 8, 8, 17, 0, tzinfo=timezone.utc)
            config = SentinelConfig.from_dict({"state_dir": str(root), "collector": {"include_processes": True, "include_listening_sockets": True, "include_auth_journal": False, "include_docker": False, "include_persistence": False, "sensitive_files": []}, "dashboard": {"enabled": False}, "self_integrity": {"enabled": False}})
            cadence = CadenceController(fast_seconds=60.0, standard_seconds=300.0, deep_seconds=300.0, maintenance_seconds=300.0)
            with CoreSentinelStore(config.storage) as store:
                service = CoreSentinelService(config, collector=EventCollector(now), store=store, cadence_controller=cadence, clock=lambda: now)
                result = service.run_cycle()
                self.assertGreaterEqual(result.findings, 1)
                state = service.contextual_pipeline.state(); self.assertEqual(state["pending_events"], 0); self.assertEqual(state["retained_events"], 1)
                health = json.loads(config.service.health_path.read_text(encoding="utf-8")); self.assertEqual(health["status"], "healthy"); self.assertEqual(health["temporal_context"]["pending_events"], 0); self.assertEqual(health["temporal_context"]["retained_events"], 1); self.assertEqual(health["safety"]["actions_executed"], 0)


if __name__ == "__main__": unittest.main()
