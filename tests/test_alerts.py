from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from quietward.alerts import LocalAlertSink
from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import StorageSettings
from quietward.contracts import EventKind, SecurityEvent
from quietward.pipeline import SentinelPipeline
from quietward.storage import SentinelStore


class AlertTests(unittest.TestCase):
    def test_high_alert_written_once_with_no_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = StorageSettings(root / "db.sqlite", root / "alerts.jsonl")
            event = SecurityEvent(
                "e1",
                datetime.now(timezone.utc),
                "host",
                "clamav",
                EventKind.MALWARE_SIGNATURE,
                "/tmp/bad",
            )
            report = SentinelPipeline().analyze([event])
            with SentinelStore(settings) as store:
                store.persist_cycle(
                    CollectionBatch(CollectorSnapshot(event.observed_at, "host"), (event,)),
                    report,
                    started_at=event.observed_at,
                    completed_at=event.observed_at,
                )
                sink = LocalAlertSink(settings.alert_log_path)
                self.assertEqual(sink.emit_pending(store), 1)
                self.assertEqual(sink.emit_pending(store), 0)
                payload = json.loads(settings.alert_log_path.read_text().strip())
                self.assertFalse(payload["explanation"]["action_authorized"])
                self.assertEqual(payload["actions_executed"], 0)
                if os.name != "nt":
                    self.assertEqual(settings.alert_log_path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
