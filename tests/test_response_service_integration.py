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
from quietward.service import QuietWardService
from quietward.storage import SentinelStore


class FakeCollector:
    host_id = "host-response-test"

    def __init__(self, batch: CollectionBatch) -> None:
        self.batch = batch

    def collect(self, previous=None) -> CollectionBatch:
        return self.batch


class BrokenResponseClient:
    def deliver_cycle(self, events, report):
        raise RuntimeError("response server unavailable")

    def poll_and_execute(self):
        raise AssertionError("poll must not run after delivery failure")


class ResponseServiceIntegrationTests(unittest.TestCase):
    def test_response_failure_is_optional_and_local_cycle_remains_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = QuietWardConfig.from_dict(
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
            now = datetime.now(timezone.utc)
            event = SecurityEvent(
                "local-response-outage-event",
                now,
                "host-response-test",
                "collector",
                EventKind.PROCESS_START,
                "process:example",
            )
            collector = FakeCollector(
                CollectionBatch(CollectorSnapshot(now, "host-response-test"), (event,))
            )
            with SentinelStore(config.storage) as store:
                service = QuietWardService(
                    config,
                    collector=collector,
                    store=store,
                    alert_sink=LocalAlertSink(config.storage.alert_log_path),
                    response_client=BrokenResponseClient(),
                    clock=lambda: now,
                )
                result = service.run_cycle()
                self.assertEqual(store.summary()["events"], 1)
                self.assertTrue(any("optional response integration" in item for item in result.errors))
                health = json.loads(config.service.health_path.read_text(encoding="utf-8"))
                self.assertEqual(health["status"], "healthy")
                self.assertEqual(health["safety"]["mode"], "observe_only")
                self.assertTrue(health["safety"]["response_integration_enabled"])
                self.assertEqual(health["safety"]["actions_executed"], 0)
                self.assertFalse(health["safety"]["system_state_modified"])


if __name__ == "__main__":
    unittest.main()
