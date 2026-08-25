from __future__ import annotations
import tempfile, unittest
from dataclasses import dataclass
from pathlib import Path
from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import SentinelConfig
from quietward.core_service import CoreSentinelService
from quietward.source_aware_lifecycle import SourceAwareIncidentLifecycleRepository
from quietward.storage import SentinelStore

@dataclass(frozen=True, slots=True)
class FakeCollectorConfig:
    sensitive_files: tuple[Path, ...] = (); include_processes: bool = False; include_sockets: bool = False; include_connections: bool = False; include_auth_journal: bool = False; include_docker: bool = False; include_persistence: bool = False
class FakeCollector:
    host_id = "host-a"
    def __init__(self) -> None: self.config = FakeCollectorConfig()
    def collect(self, previous=None) -> CollectionBatch: raise AssertionError("wiring test must not execute collection")
class ServiceLifecycleWiringTests(unittest.TestCase):
    def test_core_service_uses_source_aware_lifecycle_repository_with_sqlite_store(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); config = SentinelConfig.from_dict({"state_dir": str(root), "collector": {"include_processes": False, "include_listening_sockets": False, "include_auth_journal": False, "include_docker": False, "include_persistence": False, "sensitive_files": []}, "dashboard": {"enabled": False}, "self_integrity": {"enabled": False}})
            with SentinelStore(config.storage) as store:
                service = CoreSentinelService(config, collector=FakeCollector(), store=store)
                self.assertIsInstance(service.lifecycle_repository, SourceAwareIncidentLifecycleRepository); self.assertIs(service.lifecycle_repository.connection, store.connection); self.assertEqual(service.lifecycle_repository.summary()["actions_executed"], 0)
if __name__ == "__main__": unittest.main()
