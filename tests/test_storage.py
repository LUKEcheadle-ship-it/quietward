from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from quietward.collectors.models import CollectionBatch, CollectorSnapshot
from quietward.config import StorageSettings
from quietward.contracts import EventKind, SecurityEvent
from quietward.pipeline import SentinelPipeline
from quietward.storage import SentinelStore


class StorageTests(unittest.TestCase):
    def make_store(self, root: Path, max_events: int = 100) -> SentinelStore:
        return SentinelStore(
            StorageSettings(
                database_path=root / "quietward.sqlite3",
                alert_log_path=root / "alerts.jsonl",
                max_snapshots=10,
                max_events=max_events,
                max_findings=10,
                retention_days=30,
            )
        )

    def test_cycle_persists_and_deduplicates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            now = datetime.now(timezone.utc)
            event = SecurityEvent(
                "event-1",
                now,
                "host",
                "clamav",
                EventKind.MALWARE_SIGNATURE,
                "/tmp/bad",
            )
            snapshot = CollectorSnapshot(now, "host")
            batch = CollectionBatch(snapshot, (event,))
            report = SentinelPipeline().analyze([event])
            with self.make_store(Path(temporary)) as store:
                first = store.persist_cycle(
                    batch,
                    report,
                    started_at=now,
                    completed_at=now,
                )
                second = store.persist_cycle(
                    batch,
                    report,
                    started_at=now,
                    completed_at=now,
                )
                self.assertEqual(first.events_inserted, 1)
                self.assertEqual(second.events_inserted, 0)
                self.assertEqual(store.summary()["events"], 1)
                self.assertEqual(store.summary()["actions_executed"], 0)
                self.assertEqual(store.latest_snapshot(), snapshot)

    def test_executable_proposal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            now = datetime.now(timezone.utc)
            event = SecurityEvent(
                "event-1",
                now,
                "host",
                "clamav",
                EventKind.MALWARE_SIGNATURE,
                "/tmp/bad",
            )
            report = SentinelPipeline().analyze([event])
            object.__setattr__(
                report.action_proposals[0],
                "executable_in_current_mode",
                True,
            )
            with self.make_store(Path(temporary)) as store:
                with self.assertRaisesRegex(ValueError, "executable"):
                    store.persist_cycle(
                        CollectionBatch(CollectorSnapshot(now, "host"), (event,)),
                        report,
                        started_at=now,
                        completed_at=now,
                    )

    def test_retention_keeps_latest_events(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.make_store(Path(temporary), max_events=2) as store:
                for index in range(3):
                    now = datetime.now(timezone.utc)
                    event = SecurityEvent(
                        f"event-{index}",
                        now,
                        "host",
                        "test",
                        EventKind.FILE_CHANGE,
                        f"/tmp/{index}",
                    )
                    store.persist_cycle(
                        CollectionBatch(CollectorSnapshot(now, "host"), (event,)),
                        SentinelPipeline().analyze([event]),
                        started_at=now,
                        completed_at=now,
                    )
                self.assertEqual(store.summary()["events"], 2)

    def test_high_findings_are_pending_until_marked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            now = datetime.now(timezone.utc)
            event = SecurityEvent(
                "event-1",
                now,
                "host",
                "clamav",
                EventKind.MALWARE_SIGNATURE,
                "/tmp/bad",
            )
            report = SentinelPipeline().analyze([event])
            with self.make_store(Path(temporary)) as store:
                store.persist_cycle(
                    CollectionBatch(CollectorSnapshot(now, "host"), (event,)),
                    report,
                    started_at=now,
                    completed_at=now,
                )
                pending = store.pending_alert_findings()
                self.assertEqual(len(pending), 1)
                store.mark_alerted(pending[0])
                self.assertEqual(store.pending_alert_findings(), [])


if __name__ == "__main__":
    unittest.main()
