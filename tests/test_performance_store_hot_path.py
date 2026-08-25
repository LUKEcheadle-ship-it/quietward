from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import StorageSettings
from quietward.contracts import EventKind, SecurityEvent
from quietward.performance_store import PerformanceSentinelStore
from quietward.pipeline import SentinelPipeline
from quietward.storage import SentinelStore


class PerformanceStoreHotPathTests(unittest.TestCase):
    def settings(self, root: Path) -> StorageSettings:
        return StorageSettings(
            database_path=root / "sentinel.sqlite3",
            alert_log_path=root / "alerts.jsonl",
        )

    def test_latest_snapshot_is_cached_after_successful_persist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            now = datetime(2026, 8, 7, 22, 0, tzinfo=timezone.utc)
            snapshot = CollectorSnapshot(now, "host-test")
            event = SecurityEvent(
                "evt-1",
                now,
                "host-test",
                "test",
                EventKind.FILE_CHANGE,
                "subject",
            )
            batch = CollectionBatch(snapshot, (event,))
            report = SentinelPipeline().analyze([event])
            with PerformanceSentinelStore(self.settings(root)) as store:
                store.persist_cycle(
                    batch,
                    report,
                    started_at=now,
                    completed_at=now,
                )
                with mock.patch.object(
                    SentinelStore,
                    "latest_snapshot",
                    side_effect=AssertionError("database reload should not run"),
                ):
                    self.assertEqual(store.latest_snapshot(), snapshot)
                    self.assertEqual(store.latest_snapshot(), snapshot)

    def test_runtime_summary_reuses_counts_inside_ttl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            clock = [100.0]
            with PerformanceSentinelStore(
                self.settings(Path(temporary)),
                runtime_summary_cache_seconds=300.0,
                monotonic=lambda: clock[0],
            ) as store:
                first = store.runtime_summary()
                self.assertFalse(first["runtime_summary_cached"])
                clock[0] = 120.0
                with mock.patch.object(
                    SentinelStore,
                    "summary",
                    side_effect=AssertionError("full summary should stay cached"),
                ):
                    second = store.runtime_summary()
                self.assertTrue(second["runtime_summary_cached"])
                self.assertEqual(second["runtime_summary_cache_age_seconds"], 20.0)
                self.assertEqual(second["actions_executed"], 0)

    def test_unchanged_evidence_status_metadata_is_checkpointed_not_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            clock = [100.0]
            with PerformanceSentinelStore(
                self.settings(Path(temporary)),
                monotonic=lambda: clock[0],
            ) as store:
                with mock.patch.object(
                    store,
                    "set_metadata",
                    wraps=store.set_metadata,
                ) as setter:
                    store.verify_evidence_chain()
                    first_count = setter.call_count
                    self.assertGreaterEqual(first_count, 1)

                    clock[0] = 120.0
                    store.verify_evidence_chain()
                    self.assertEqual(
                        setter.call_count,
                        first_count,
                        "same chain head should not rewrite dashboard fallback metadata",
                    )

                    clock[0] = 400.0
                    store.verify_evidence_chain()
                    self.assertGreater(setter.call_count, first_count)

    def test_explicit_summary_stays_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with PerformanceSentinelStore(self.settings(Path(temporary))) as store:
                store.runtime_summary()
                explicit = store.summary()
            self.assertIn("cycles", explicit)
            self.assertNotIn("runtime_summary_cached", explicit)


if __name__ == "__main__":
    unittest.main()
