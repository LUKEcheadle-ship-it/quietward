from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from quietward.cadence import CadenceController, CadenceLane
from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import SentinelConfig
from quietward.core_service import CoreSentinelService
from quietward.core_store import CoreSentinelStore
from quietward.scanners.execution import ScannerExecutionResult
from quietward.storage import SentinelStore


@dataclass(frozen=True, slots=True)
class FakeCollectorConfig:
    sensitive_files: tuple[Path, ...] = ()
    include_processes: bool = True
    include_sockets: bool = True
    include_connections: bool = False
    include_auth_journal: bool = False
    include_docker: bool = False
    include_persistence: bool = False


@dataclass(frozen=True, slots=True)
class FakeWindowsCollectorConfig:
    sensitive_files: tuple[Path, ...] = ()
    include_processes: bool = True
    include_sockets: bool = True
    include_connections: bool = False
    include_auth_events: bool = False
    include_docker: bool = False
    include_persistence: bool = True


class FakeCollector:
    host_id = "host-a"

    def __init__(self) -> None:
        self.config = FakeCollectorConfig()

    def collect(self, previous=None) -> CollectionBatch:
        return CollectionBatch(
            CollectorSnapshot(
                datetime.now(timezone.utc),
                self.host_id,
                collector_version="fake-read-only-v1",
            ),
            (),
        )


class FakeWindowsCollector:
    host_id = "host-windows"

    def __init__(self) -> None:
        self.config = FakeWindowsCollectorConfig()
        self.runner = None

    def collect(self, previous=None) -> CollectionBatch:
        return CollectionBatch(
            CollectorSnapshot(
                datetime.now(timezone.utc),
                self.host_id,
                collector_version="windows-read-only-v1",
            ),
            (),
        )


class FakeScannerExecutor:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, job):
        self.calls += 1
        now = datetime.now(timezone.utc)
        return (
            ScannerExecutionResult(
                scanner=job.scanner,
                target=None,
                started_at=now,
                completed_at=now,
                status="ok",
                returncode=0,
                events=(),
            ),
        )


class CoreServiceTests(unittest.TestCase):
    def test_due_scanner_waits_for_maintenance_lane(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            scanner_data = root / "fresh.cvd"
            scanner_data.write_text("data", encoding="utf-8")
            config = SentinelConfig.from_dict(
                {
                    "state_dir": str(root),
                    "collector": {
                        "include_auth_journal": False,
                        "include_docker": False,
                        "include_persistence": False,
                        "sensitive_files": [],
                    },
                    "dashboard": {"enabled": False},
                    "self_integrity": {"enabled": False},
                    "scanners": [
                        {
                            "scanner": "clamav",
                            "enabled": True,
                            "interval_seconds": 1,
                            "timeout_seconds": 1,
                            "data_source": str(scanner_data),
                        }
                    ],
                }
            )
            monotonic = [0.0]
            cadence = CadenceController(
                fast_seconds=60.0,
                standard_seconds=300.0,
                deep_seconds=300.0,
                maintenance_seconds=300.0,
                monotonic=lambda: monotonic[0],
            )
            cadence.mark_completed(set(CadenceLane))
            scanner = FakeScannerExecutor()
            with SentinelStore(config.storage) as store:
                service = CoreSentinelService(
                    config,
                    collector=FakeCollector(),
                    store=store,
                    scanner_executor=scanner,
                    cadence_controller=cadence,
                )

                monotonic[0] = 60.0
                fast = service.run_cycle()
                self.assertEqual(scanner.calls, 0)
                self.assertEqual(fast.scanner_runs, 0)
                scanner_domain = next(
                    item
                    for item in fast.coverage["domains"]
                    if item["name"] == "scanner:clamav:0"
                )
                self.assertEqual(scanner_domain["state"], "not_due")
                self.assertTrue(fast.coverage["operationally_healthy"])

                monotonic[0] = 300.0
                maintenance = service.run_cycle()
                self.assertEqual(scanner.calls, 1)
                self.assertEqual(maintenance.scanner_runs, 1)
                scanner_domain = next(
                    item
                    for item in maintenance.coverage["domains"]
                    if item["name"] == "scanner:clamav:0"
                )
                self.assertEqual(scanner_domain["state"], "complete")

    def test_windows_fast_scope_excludes_persistence_until_standard_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            config = SentinelConfig.from_dict(
                {
                    "state_dir": str(root),
                    "collector": {
                        "type": "windows",
                        "include_processes": True,
                        "include_listening_sockets": True,
                        "include_outbound_connections": False,
                        "include_auth_journal": False,
                        "include_docker": False,
                        "include_persistence": True,
                        "sensitive_files": [],
                    },
                    "dashboard": {"enabled": False},
                    "self_integrity": {"enabled": False},
                }
            )
            monotonic = [0.0]
            cadence = CadenceController(
                fast_seconds=60.0,
                standard_seconds=300.0,
                deep_seconds=300.0,
                maintenance_seconds=300.0,
                monotonic=lambda: monotonic[0],
            )
            cadence.mark_completed(set(CadenceLane))
            with CoreSentinelStore(
                config.storage,
                monotonic=lambda: monotonic[0],
            ) as store:
                service = CoreSentinelService(
                    config,
                    collector=FakeWindowsCollector(),
                    store=store,
                    cadence_controller=cadence,
                )

                monotonic[0] = 60.0
                fast_result = service.run_cycle()
                fast_state = store.maintenance_state()
                self.assertEqual(
                    fast_result.coverage["cadence"]["due_lanes"],
                    ["fast"],
                )
                self.assertIn("processes", fast_state["cycle_observation_domains"])
                self.assertIn(
                    "listening_sockets",
                    fast_state["cycle_observation_domains"],
                )
                self.assertNotIn(
                    "persistence",
                    fast_state["cycle_observation_domains"],
                )

                monotonic[0] = 300.0
                standard_result = service.run_cycle()
                standard_state = store.maintenance_state()
                self.assertIn(
                    "standard",
                    standard_result.coverage["cadence"]["due_lanes"],
                )
                self.assertIn(
                    "persistence",
                    standard_state["cycle_observation_domains"],
                )


if __name__ == "__main__":
    unittest.main()
