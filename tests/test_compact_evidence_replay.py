from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import StorageSettings
from quietward.maintenance_store import MaintenanceSentinelStore
from quietward.pipeline import SentinelPipeline
from quietward.source_aware_lifecycle import SourceAwareIncidentLifecycleRepository


class CompactEvidenceReplayTests(unittest.TestCase):
    def test_quiet_reference_cycles_replay_without_snapshot_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = StorageSettings(database_path=root / "quietward.sqlite3", alert_log_path=root / "alerts.jsonl")
            monotonic = [0.0]
            now = datetime(2026, 8, 8, 4, 0, tzinfo=timezone.utc)
            report = SentinelPipeline().analyze([])
            with MaintenanceSentinelStore(settings, quiet_durable_interval_seconds=30.0, monotonic=lambda: monotonic[0]) as store:
                first = store.persist_cycle(CollectionBatch(CollectorSnapshot(now, "host"), ()), report, started_at=now, completed_at=now)
                monotonic[0] = 60.0
                now += timedelta(minutes=1)
                second = store.persist_cycle(CollectionBatch(CollectorSnapshot(now, "host"), ()), report, started_at=now, completed_at=now)
                self.assertNotEqual(second.cycle_id, first.cycle_id)
                self.assertEqual(second.snapshot_id, first.snapshot_id)
                self.assertTrue(store.verify_evidence_chain()["valid"])
                lifecycle = SourceAwareIncidentLifecycleRepository(store.connection)
                replayed = lifecycle.catch_up_from_evidence_chain(up_to_cycle_id=second.cycle_id)
                self.assertEqual(replayed, 2)
                self.assertEqual(lifecycle.last_processed_cycle_id(), second.cycle_id)
                self.assertEqual(lifecycle.active_count(), 0)


if __name__ == "__main__": unittest.main()
