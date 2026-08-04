from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import QuietWardConfig
from quietward.service import QuietWardService
from quietward.storage import SentinelStore


class StableCollector:
    host_id = "soak-host"

    def __init__(self) -> None:
        self.index = 0

    def collect(self, previous: CollectorSnapshot | None = None) -> CollectionBatch:
        self.index += 1
        observed = datetime(2026, 7, 30, tzinfo=timezone.utc) + timedelta(
            seconds=self.index
        )
        return CollectionBatch(CollectorSnapshot(observed, self.host_id), ())


class SoakTests(unittest.TestCase):
    def test_hundred_restart_safe_cycles_remain_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = QuietWardConfig.from_dict(
                {
                    "state_dir": str(root),
                    "storage": {
                        "database_path": str(root / "db.sqlite"),
                        "alert_log_path": str(root / "alerts.jsonl"),
                        "max_snapshots": 25,
                        "max_events": 100,
                        "max_findings": 100,
                        "retention_days": 30,
                    },
                    "dashboard": {"enabled": False},
                    "collector": {
                        "include_auth_journal": False,
                        "include_docker": False,
                    },
                }
            )
            collector = StableCollector()
            with SentinelStore(config.storage) as store:
                service = QuietWardService(config, collector=collector, store=store)
                for _ in range(50):
                    self.assertEqual(
                        service.run_cycle().to_dict()["actions_executed"],
                        0,
                    )
            with SentinelStore(config.storage) as store:
                service = QuietWardService(config, collector=collector, store=store)
                for _ in range(50):
                    service.run_cycle()
                summary = store.summary()
                self.assertEqual(summary["snapshots"], 25)
                self.assertEqual(summary["events"], 0)
                self.assertEqual(summary["actions_executed"], 0)


if __name__ == "__main__":
    unittest.main()
