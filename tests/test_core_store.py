from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quietward.cadence import CadenceLane
from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import StorageSettings
from quietward.contracts import EventKind, SecurityEvent
from quietward.core_store import CoreSentinelStore
from quietward.pipeline import SentinelPipeline
from quietward.source_aware_lifecycle import SourceAwareIncidentLifecycleRepository


class CoreStoreTests(unittest.TestCase):
    def test_not_due_active_incident_does_not_force_unrelated_fast_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = StorageSettings(
                database_path=root / "sentinel.sqlite3",
                alert_log_path=root / "alerts.jsonl",
            )
            monotonic = [0.0]
            now = datetime(2026, 8, 8, 9, 0, tzinfo=timezone.utc)
            with CoreSentinelStore(
                settings,
                monotonic=lambda: monotonic[0],
            ) as store:
                lifecycle = SourceAwareIncidentLifecycleRepository(store.connection)
                event = SecurityEvent(
                    "persistence-1",
                    now,
                    "host-a",
                    "windows_persistence_snapshot",
                    EventKind.PERSISTENCE_CHANGE,
                    "windows:persistence:item",
                    {
                        "persistence_indicator": True,
                        "baseline_deviation": 1.0,
                    },
                )
                report = SentinelPipeline().analyze([event])
                first = store.persist_cycle(
                    CollectionBatch(
                        CollectorSnapshot(
                            now,
                            "host-a",
                            collector_version="windows-read-only-v1",
                        ),
                        (event,),
                    ),
                    report,
                    started_at=now,
                    completed_at=now,
                )
                lifecycle.reconcile_cycle(
                    first.cycle_id,
                    (finding.to_dict() for finding in report.findings),
                    (event.to_dict(),),
                    observed_at=now,
                    coverage_complete=True,
                    coverage_domains=[
                        {"name": "persistence", "state": "complete"},
                    ],
                )
                self.assertEqual(lifecycle.active_count(), 1)
                self.assertEqual(
                    store.active_incident_lanes(),
                    frozenset({CadenceLane.STANDARD}),
                )

                monotonic[0] = 60.0
                now += timedelta(minutes=1)
                store.set_cycle_observation_scope(
                    {"processes", "listening_sockets"},
                    {CadenceLane.FAST},
                )
                empty = SentinelPipeline().analyze([])
                fast = store.persist_cycle(
                    CollectionBatch(
                        CollectorSnapshot(
                            now,
                            "host-a",
                            collector_version="windows-read-only-v1",
                        ),
                        (),
                    ),
                    empty,
                    started_at=now,
                    completed_at=now,
                )
                self.assertEqual(fast.cycle_id, first.cycle_id)
                self.assertEqual(store.persistence_mode, "volatile")
                self.assertEqual(store.summary()["cycles"], 1)

                monotonic[0] = 120.0
                now += timedelta(minutes=1)
                store.set_cycle_observation_scope(
                    {"persistence"},
                    {CadenceLane.STANDARD},
                )
                relevant = store.persist_cycle(
                    CollectionBatch(
                        CollectorSnapshot(
                            now,
                            "host-a",
                            collector_version="windows-read-only-v1",
                        ),
                        (),
                    ),
                    empty,
                    started_at=now,
                    completed_at=now,
                )
                self.assertNotEqual(relevant.cycle_id, first.cycle_id)
                self.assertEqual(store.persistence_mode, "reference")
                self.assertEqual(store.summary()["cycles"], 2)

    def test_scanner_and_self_integrity_incidents_protect_heavy_lanes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = StorageSettings(
                database_path=root / "sentinel.sqlite3",
                alert_log_path=root / "alerts.jsonl",
            )
            now = datetime(2026, 8, 8, 9, 30, tzinfo=timezone.utc)
            events = [
                SecurityEvent(
                    "malware-1",
                    now,
                    "host-a",
                    "clamav",
                    EventKind.MALWARE_SIGNATURE,
                    "/tmp/bad",
                    {"authoritative_rule_match": True},
                ),
                SecurityEvent(
                    "integrity-1",
                    now,
                    "host-a",
                    "quietward_self_integrity",
                    EventKind.SELF_INTEGRITY_CHANGE,
                    "/opt/quietward/module.py",
                    {
                        "authoritative_rule_match": True,
                        "baseline_deviation": 1.0,
                    },
                ),
            ]
            with CoreSentinelStore(settings) as store:
                lifecycle = SourceAwareIncidentLifecycleRepository(store.connection)
                report = SentinelPipeline().analyze(events)
                persisted = store.persist_cycle(
                    CollectionBatch(
                        CollectorSnapshot(now, "host-a"),
                        tuple(events),
                    ),
                    report,
                    started_at=now,
                    completed_at=now,
                )
                lifecycle.reconcile_cycle(
                    persisted.cycle_id,
                    (finding.to_dict() for finding in report.findings),
                    (event.to_dict() for event in events),
                    observed_at=now,
                    coverage_complete=True,
                    coverage_domains=[
                        {"name": "scanner:clamav:0", "state": "complete"},
                        {"name": "self_integrity", "state": "complete"},
                    ],
                )
                lanes = store.active_incident_lanes()

            self.assertIn(CadenceLane.MAINTENANCE, lanes)
            self.assertIn(CadenceLane.DEEP, lanes)


if __name__ == "__main__":
    unittest.main()
