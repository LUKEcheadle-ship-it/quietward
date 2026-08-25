from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import StorageSettings
from quietward.contracts import EventKind, SecurityEvent
from quietward.maintenance_store import MaintenanceSentinelStore
from quietward.pipeline import SentinelPipeline


class MaintenanceStoreTests(unittest.TestCase):
    def settings(self, root: Path) -> StorageSettings:
        return StorageSettings(database_path=root / "quietward.sqlite3", alert_log_path=root / "alerts.jsonl", max_snapshots=1, max_cycles=20)

    def test_fully_quiet_cycles_are_volatile_until_full_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); monotonic = [0.0]; now = datetime(2026, 8, 8, 2, 0, tzinfo=timezone.utc); report = SentinelPipeline().analyze([])
            with MaintenanceSentinelStore(self.settings(root), prune_interval_seconds=300.0, full_snapshot_interval_seconds=300.0, quiet_durable_interval_seconds=300.0, monotonic=lambda: monotonic[0]) as store:
                first = store.persist_cycle(CollectionBatch(CollectorSnapshot(now, "host"), ()), report, started_at=now, completed_at=now)
                self.assertEqual(store.summary()["cycles"], 1); self.assertEqual(store.summary()["snapshots"], 1)
                monotonic[0] = 60.0; now += timedelta(minutes=1)
                second = store.persist_cycle(CollectionBatch(CollectorSnapshot(now, "host"), ()), report, started_at=now, completed_at=now)
                self.assertEqual(second.cycle_id, first.cycle_id); self.assertEqual(second.snapshot_id, first.snapshot_id); self.assertEqual(store.summary()["cycles"], 1); self.assertEqual(store.summary()["snapshots"], 1)
                state = store.maintenance_state(); self.assertEqual(state["quiet_cycles_volatile"], 1); self.assertEqual(state["quiet_cycles_compacted"], 0)
                monotonic[0] = 300.0; now += timedelta(minutes=4)
                third = store.persist_cycle(CollectionBatch(CollectorSnapshot(now, "host"), ()), report, started_at=now, completed_at=now)
                self.assertNotEqual(third.cycle_id, first.cycle_id); self.assertNotEqual(third.snapshot_id, first.snapshot_id); self.assertEqual(store.summary()["cycles"], 2); self.assertEqual(store.summary()["snapshots"], 1); self.assertTrue(store.verify_evidence_chain()["valid"])
                state = store.maintenance_state(); self.assertEqual(state["seconds_since_full_snapshot"], 0.0); self.assertEqual(state["seconds_since_durable_cycle"], 0.0); self.assertEqual(state["actions_executed"], 0)

    def test_signed_reference_heartbeat_is_used_when_durable_interval_is_shorter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); monotonic = [0.0]; now = datetime(2026, 8, 8, 2, 30, tzinfo=timezone.utc); report = SentinelPipeline().analyze([])
            with MaintenanceSentinelStore(self.settings(root), full_snapshot_interval_seconds=300.0, quiet_durable_interval_seconds=30.0, monotonic=lambda: monotonic[0]) as store:
                first = store.persist_cycle(CollectionBatch(CollectorSnapshot(now, "host"), ()), report, started_at=now, completed_at=now)
                monotonic[0] = 60.0; now += timedelta(minutes=1)
                second = store.persist_cycle(CollectionBatch(CollectorSnapshot(now, "host"), ()), report, started_at=now, completed_at=now)
                self.assertNotEqual(second.cycle_id, first.cycle_id); self.assertEqual(second.snapshot_id, first.snapshot_id)
                payload = json.loads(store.connection.execute("SELECT payload_json FROM evidence_chain WHERE cycle_id=?", (second.cycle_id,)).fetchone()[0])
                self.assertTrue(payload["quiet_cycle"]); self.assertEqual(payload["snapshot_mode"], "reference"); self.assertTrue(store.verify_evidence_chain()["valid"]); self.assertEqual(store.maintenance_state()["quiet_cycles_compacted"], 1)

    def test_event_bearing_cycle_forces_full_snapshot_between_checkpoints(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); monotonic = [0.0]; now = datetime(2026, 8, 8, 3, 0, tzinfo=timezone.utc); empty = SentinelPipeline().analyze([])
            with MaintenanceSentinelStore(self.settings(root), monotonic=lambda: monotonic[0]) as store:
                first = store.persist_cycle(CollectionBatch(CollectorSnapshot(now, "host"), ()), empty, started_at=now, completed_at=now)
                monotonic[0] = 60.0; now += timedelta(minutes=1)
                event = SecurityEvent("event-1", now, "host", "test", EventKind.NEW_LISTENING_PORT, "tcp://*:4444"); report = SentinelPipeline().analyze([event])
                second = store.persist_cycle(CollectionBatch(CollectorSnapshot(now, "host"), (event,)), report, started_at=now, completed_at=now)
                self.assertNotEqual(second.cycle_id, first.cycle_id); self.assertNotEqual(second.snapshot_id, first.snapshot_id)
                payload = json.loads(store.connection.execute("SELECT payload_json FROM evidence_chain WHERE cycle_id=?", (second.cycle_id,)).fetchone()[0]); self.assertNotIn("quiet_cycle", payload); self.assertTrue(store.verify_evidence_chain()["valid"])


if __name__ == "__main__": unittest.main()
