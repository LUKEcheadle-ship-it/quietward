from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import StorageSettings
from quietward.contracts import EventKind, SecurityEvent
from quietward.operational_findings import current_findings, pending_incident_alert_findings
from quietward.pipeline import SentinelPipeline
from quietward.product_store import ProductSentinelStore
from quietward.source_aware_lifecycle import SourceAwareIncidentLifecycleRepository


class OperationalFindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup); root = Path(self.temporary.name)
        self.settings = StorageSettings(database_path=root / "quietward.sqlite3", alert_log_path=root / "alerts.jsonl")
        self.now = datetime(2026, 8, 8, 6, 0, tzinfo=timezone.utc)

    def event(self, event_id: str, *, privileged: bool = False) -> SecurityEvent:
        return SecurityEvent(event_id, self.now, "host-a", "windows_persistence_snapshot", EventKind.PERSISTENCE_CHANGE, "windows:persistence:shared", {"persistence_indicator": True, "baseline_deviation": 1.0, "privileged_context": privileged})

    def persist_and_reconcile(self, store: ProductSentinelStore, lifecycle: SourceAwareIncidentLifecycleRepository, cycle_id: int, events: list[SecurityEvent]):
        report = SentinelPipeline().analyze(events); observed = self.now + timedelta(minutes=cycle_id - 1)
        persisted = store.persist_cycle(CollectionBatch(CollectorSnapshot(observed, "host-a"), tuple(events)), report, started_at=observed, completed_at=observed); self.assertEqual(persisted.cycle_id, cycle_id)
        lifecycle.reconcile_cycle(cycle_id, (finding.to_dict() for finding in report.findings), (event.to_dict() for event in events), observed_at=observed, coverage_complete=True, coverage_domains=[{"name": "persistence", "state": "complete"}])
        return report

    def transition_count(self, store: ProductSentinelStore) -> int:
        return int(store.connection.execute("SELECT COUNT(*) FROM incident_lifecycle_transitions").fetchone()[0])

    def test_current_projection_and_alerts_follow_incident_transitions(self) -> None:
        with ProductSentinelStore(self.settings) as store:
            lifecycle = SourceAwareIncidentLifecycleRepository(store.connection)
            first_report = self.persist_and_reconcile(store, lifecycle, 1, [self.event("e1")]); first_id = first_report.findings[0].finding_id; first_score = first_report.findings[0].score
            self.assertEqual(self.transition_count(store), 1); first_pending = pending_incident_alert_findings(store, now=self.now); self.assertEqual([item["finding_id"] for item in first_pending], [first_id]); store.mark_alerted(first_pending[0])
            self.now += timedelta(minutes=1); second_report = self.persist_and_reconcile(store, lifecycle, 2, [self.event("e2")]); second_id = second_report.findings[0].finding_id
            self.assertNotEqual(second_id, first_id); self.assertEqual(self.transition_count(store), 1); self.assertEqual(pending_incident_alert_findings(store, now=self.now), [])
            compact = current_findings(store, limit=100); self.assertEqual(len(compact), 1); self.assertEqual(compact[0]["finding_id"], second_id); self.assertEqual(compact[0]["incident"]["state"], "recurring"); self.assertEqual(len(store.recent_findings(100)), 2)
            self.now += timedelta(minutes=1); changed_report = self.persist_and_reconcile(store, lifecycle, 3, [self.event("e3", privileged=True)]); changed_id = changed_report.findings[0].finding_id; changed_score = changed_report.findings[0].score
            self.assertGreater(changed_score, first_score); self.assertEqual(self.transition_count(store), 2); changed_pending = pending_incident_alert_findings(store, now=self.now); self.assertEqual([item["finding_id"] for item in changed_pending], [changed_id]); self.assertEqual(changed_pending[0]["incident"]["state"], "changed"); store.mark_alerted(changed_pending[0])
            self.now += timedelta(minutes=1); deescalated_report = self.persist_and_reconcile(store, lifecycle, 4, [self.event("e4", privileged=False)]); deescalated = deescalated_report.findings[0]
            self.assertLess(deescalated.score, changed_score); self.assertEqual(self.transition_count(store), 3); self.assertEqual(pending_incident_alert_findings(store, now=self.now), [])
            self.now += timedelta(minutes=1); empty = self.persist_and_reconcile(store, lifecycle, 5, []); self.assertEqual(empty.findings, ()); self.assertEqual(lifecycle.active_count(), 0); self.assertEqual(self.transition_count(store), 4); self.assertEqual(current_findings(store, limit=100, active_only=True), []); self.assertGreater(len(store.recent_findings(100)), 0)
            self.now += timedelta(minutes=1); reappeared_report = self.persist_and_reconcile(store, lifecycle, 6, [self.event("e6", privileged=True)]); reappeared_id = reappeared_report.findings[0].finding_id
            self.assertEqual(self.transition_count(store), 5); reappeared = pending_incident_alert_findings(store, now=self.now); self.assertEqual([item["finding_id"] for item in reappeared], [reappeared_id]); self.assertTrue(reappeared[0]["incident"]["reappeared"])


if __name__ == "__main__": unittest.main()
