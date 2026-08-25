from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from quietward.alerts import LocalAlertSink
from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import QuietWardConfig
from quietward.contracts import EventKind, SecurityEvent
from quietward.locking import SingleInstanceLock
from quietward.service import QuietWardService
from quietward.storage import SentinelStore


class FakeCollector:
    host_id = "host-test"

    def __init__(self, batches: list[CollectionBatch]) -> None:
        self.batches = iter(batches)

    def collect(self, previous: CollectorSnapshot | None = None) -> CollectionBatch:
        return next(self.batches)


class FailingCollector:
    host_id = "host-test"

    def collect(self, previous: CollectorSnapshot | None = None) -> CollectionBatch:
        raise ValueError("collector failed")


class ServiceTests(unittest.TestCase):
    def config(self, root: Path) -> QuietWardConfig:
        return QuietWardConfig.from_dict(
            {
                "state_dir": str(root),
                "collector": {
                    "interval_seconds": 0.001,
                    "include_docker": False,
                    "include_auth_journal": False,
                },
                "dashboard": {"enabled": False},
            }
        )

    def test_cycle_persists_health_lifecycle_and_alert(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.config(root)
            now = datetime.now(timezone.utc)
            event = SecurityEvent(
                "e1",
                now,
                "host-test",
                "clamav",
                EventKind.MALWARE_SIGNATURE,
                "/tmp/bad",
            )
            collector = FakeCollector(
                [CollectionBatch(CollectorSnapshot(now, "host-test"), (event,))]
            )
            with SentinelStore(config.storage) as store:
                service = QuietWardService(
                    config,
                    collector=collector,
                    store=store,
                    alert_sink=LocalAlertSink(config.storage.alert_log_path),
                    clock=lambda: now,
                )
                result = service.run_cycle()
                self.assertEqual(result.findings, 1)
                self.assertIsNotNone(result.lifecycle)
                self.assertEqual(result.lifecycle["new"], 1)
                self.assertEqual(store.summary()["events"], 1)
                health = json.loads(config.service.health_path.read_text())
                self.assertEqual(health["service"], "quietward")
                self.assertEqual(health["status"], "healthy")
                self.assertEqual(health["lifecycle"]["active"], 1)
                self.assertEqual(health["safety"]["actions_executed"], 0)

    def test_lifecycle_persists_across_service_cycles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.config(root)
            now = datetime.now(timezone.utc)
            first_event = SecurityEvent(
                "e1",
                now,
                "host-test",
                "windows_socket_snapshot",
                EventKind.NEW_LISTENING_PORT,
                "listener:127.0.0.1:4444",
            )
            second_event = SecurityEvent(
                "e2",
                now,
                "host-test",
                "windows_socket_snapshot",
                EventKind.NEW_LISTENING_PORT,
                "listener:127.0.0.1:4444",
            )
            collector = FakeCollector(
                [
                    CollectionBatch(
                        CollectorSnapshot(now, "host-test"),
                        (first_event,),
                    ),
                    CollectionBatch(
                        CollectorSnapshot(now, "host-test"),
                        (second_event,),
                    ),
                ]
            )
            with SentinelStore(config.storage) as store:
                service = QuietWardService(
                    config,
                    collector=collector,
                    store=store,
                    alert_sink=LocalAlertSink(config.storage.alert_log_path),
                    clock=lambda: now,
                )
                first = service.run_cycle()
                second = service.run_cycle()
                self.assertEqual(first.lifecycle["new"], 1)
                self.assertEqual(second.lifecycle["recurring"], 1)
                incidents = service.lifecycle_repository.recent_incidents(limit=10)
                self.assertEqual(len(incidents), 1)
                self.assertEqual(incidents[0]["cycles_seen"], 2)
                self.assertEqual(incidents[0]["occurrences"], 2)
                self.assertEqual(incidents[0]["state"], "recurring")

    def test_bounded_run_returns_failure_when_cycle_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.config(root)
            with SentinelStore(config.storage) as store:
                service = QuietWardService(
                    config,
                    collector=FailingCollector(),
                    store=store,
                    alert_sink=LocalAlertSink(config.storage.alert_log_path),
                )
                with patch.object(service, "install_signal_handlers"):
                    exit_code = service.run(max_cycles=1)
                self.assertEqual(1, exit_code)
                health = json.loads(config.service.health_path.read_text())
                self.assertEqual("failed", health["status"])
                self.assertEqual(0, health["safety"]["actions_executed"])

    def test_single_instance_lock_rejects_second_holder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock"
            first = SingleInstanceLock(path)
            second = SingleInstanceLock(path)
            first.acquire()
            try:
                with self.assertRaisesRegex(RuntimeError, "another"):
                    second.acquire()
            finally:
                first.release()


if __name__ == "__main__":
    unittest.main()
