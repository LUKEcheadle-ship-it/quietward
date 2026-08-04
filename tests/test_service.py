from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

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

    def test_cycle_persists_health_and_alert(self) -> None:
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
                self.assertEqual(store.summary()["events"], 1)
                health = json.loads(config.service.health_path.read_text())
                self.assertEqual(health["service"], "quietward")
                self.assertEqual(health["status"], "healthy")
                self.assertEqual(health["safety"]["actions_executed"], 0)

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
