from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import StorageSettings
from quietward.contracts import EventKind, SecurityEvent
from quietward.pipeline import SentinelPipeline
from quietward.product_store import ProductSentinelStore


class ContextualSuppressionFailClosedTests(unittest.TestCase):
    def test_missing_source_cycle_records_review_but_creates_no_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = StorageSettings(
                database_path=root / "sentinel.sqlite3",
                alert_log_path=root / "alerts.jsonl",
            )
            now = datetime(2026, 8, 8, 18, 0, tzinfo=timezone.utc)
            event = SecurityEvent(
                "listener-reviewed",
                now,
                "host-a",
                "windows_socket_snapshot",
                EventKind.NEW_LISTENING_PORT,
                "tcp://0.0.0.0:4999",
                {"external_bind": True},
            )
            report = SentinelPipeline().analyze([event])
            self.assertEqual(len(report.findings), 1)
            finding_id = report.findings[0].finding_id

            with ProductSentinelStore(settings) as store:
                persisted = store.persist_cycle(
                    CollectionBatch(
                        CollectorSnapshot(now, "host-a"),
                        (event,),
                    ),
                    report,
                    started_at=now,
                    completed_at=now,
                )
                store.connection.execute(
                    "UPDATE evidence_chain SET payload_json='{}' WHERE cycle_id=?",
                    (persisted.cycle_id,),
                )
                store.connection.commit()

                review = store.set_finding_state(
                    finding_id,
                    "expected",
                    note="reviewed but source cycle unavailable",
                    create_rule=True,
                )
                self.assertEqual(review["state"], "expected")
                rules = int(
                    store.connection.execute(
                        "SELECT COUNT(*) FROM suppression_rules WHERE source_finding_id=?",
                        (finding_id,),
                    ).fetchone()[0]
                )
                self.assertEqual(rules, 0)

                kept, suppressed = store.filter_suppressed_events([event], now=now)
                self.assertEqual([item.event_id for item in kept], ["listener-reviewed"])
                self.assertEqual(suppressed, [])


if __name__ == "__main__":
    unittest.main()
