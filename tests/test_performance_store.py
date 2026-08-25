from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import StorageSettings
from quietward.contracts import EventKind, SecurityEvent
from quietward.performance_store import PerformanceSentinelStore
from quietward.pipeline import SentinelPipeline


class Clock:
    def __init__(self) -> None:
        self.value = 0.0
    def __call__(self) -> float:
        return self.value


class PerformanceStoreTests(unittest.TestCase):
    def make_store(self, root: Path, clock: Clock) -> PerformanceSentinelStore:
        return PerformanceSentinelStore(StorageSettings(database_path=root / "quietward.sqlite3", alert_log_path=root / "alerts.jsonl"), full_audit_interval_seconds=300.0, monotonic=clock)

    def persist_event(self, store: PerformanceSentinelStore, event_id: str) -> int:
        now = datetime.now(timezone.utc)
        event = SecurityEvent(event_id, now, "host", "test", EventKind.FILE_CHANGE, f"subject:{event_id}")
        report = SentinelPipeline().analyze([event])
        return store.persist_cycle(CollectionBatch(CollectorSnapshot(now, "host"), (event,)), report, started_at=now, completed_at=now).cycle_id

    def test_first_check_is_full_new_rows_incremental_then_unchanged_is_cached(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            clock = Clock()
            with self.make_store(Path(temporary), clock) as store:
                first = store.verify_evidence_chain()
                self.assertTrue(first["valid"])
                self.assertEqual(first["verification_mode"], "full")
                self.persist_event(store, "event-1")
                clock.value = 1.0
                second = store.verify_evidence_chain()
                self.assertTrue(second["valid"])
                self.assertEqual(second["verification_mode"], "incremental")
                self.assertEqual(second["cycles_checked"], 1)
                self.assertEqual(second["cycles_checked_this_pass"], 1)
                clock.value = 2.0
                third = store.verify_evidence_chain()
                self.assertTrue(third["valid"])
                self.assertEqual(third["verification_mode"], "cached_unchanged")
                self.assertTrue(third["verification_reused"])
                self.assertEqual(third["cycles_checked_this_pass"], 0)
                self.persist_event(store, "event-2")
                clock.value = 3.0
                fourth = store.verify_evidence_chain()
                self.assertEqual(fourth["verification_mode"], "incremental")
                self.assertEqual(fourth["cycles_checked_this_pass"], 1)
                self.assertEqual(fourth["cycles_checked"], 2)

    def test_new_row_tampering_triggers_full_fallback_and_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            clock = Clock()
            with self.make_store(Path(temporary), clock) as store:
                store.verify_evidence_chain()
                cycle = self.persist_event(store, "event-new")
                store.connection.execute("UPDATE evidence_chain SET payload_json='tampered' WHERE cycle_id=?", (cycle,))
                store.connection.commit()
                clock.value = 1.0
                result = store.verify_evidence_chain()
                self.assertFalse(result["valid"])
                self.assertEqual(result["verification_mode"], "full")
                self.assertTrue(result["incremental_fallback_triggered"])
                self.assertTrue(any("payload hash mismatch" in item for item in result["errors"]))

    def test_periodic_full_audit_detects_retroactive_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            clock = Clock()
            with self.make_store(Path(temporary), clock) as store:
                store.verify_evidence_chain()
                cycle = self.persist_event(store, "event-old")
                clock.value = 1.0
                self.assertTrue(store.verify_evidence_chain()["valid"])
                store.connection.execute("UPDATE evidence_chain SET payload_json='retroactive-tamper' WHERE cycle_id=?", (cycle,))
                store.connection.commit()
                clock.value = 2.0
                between_audits = store.verify_evidence_chain()
                self.assertTrue(between_audits["valid"])
                self.assertEqual(between_audits["verification_mode"], "cached_unchanged")
                self.assertEqual(between_audits["cycles_checked_this_pass"], 0)
                clock.value = 301.0
                full = store.verify_evidence_chain()
                self.assertFalse(full["valid"])
                self.assertEqual(full["verification_mode"], "full")


if __name__ == "__main__":
    unittest.main()
