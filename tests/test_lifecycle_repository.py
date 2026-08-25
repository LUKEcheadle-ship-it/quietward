from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

from quietward.lifecycle_repository import IncidentLifecycleRepository


class LifecycleRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.now = datetime(2026, 8, 7, 20, 0, tzinfo=timezone.utc)
        self.finding = {"finding_id": "fsf-a", "host_id": "host-a", "subject": "C:/Program Files/Example/example.exe", "severity": "high", "score": 82.0, "evidence_event_ids": ["event-a"]}
        self.events = [{"event_id": "event-a", "kind": "new_listening_port", "source": "windows", "observed_at": "2026-08-07T20:00:00Z"}]
    def tearDown(self) -> None: self.connection.close()

    def test_state_survives_repository_reopen_and_recurrence(self) -> None:
        repository = IncidentLifecycleRepository(self.connection)
        first = repository.reconcile_cycle(1, [self.finding], self.events, observed_at=self.now, coverage_complete=True)
        self.assertEqual(first.new, 1); self.assertEqual(first.active_total, 1)
        reopened = IncidentLifecycleRepository(self.connection); recurring_finding = dict(self.finding); recurring_finding["finding_id"] = "fsf-b"
        recurring = reopened.reconcile_cycle(2, [recurring_finding], self.events, observed_at=self.now + timedelta(minutes=1), coverage_complete=True)
        self.assertEqual(recurring.recurring, 1); incident = reopened.recent_incidents(limit=1)[0]; self.assertEqual(incident["state"], "recurring"); self.assertEqual(incident["cycles_seen"], 2); self.assertEqual(incident["occurrences"], 2); self.assertTrue(incident["active"])

    def test_material_change_is_persisted_as_changed(self) -> None:
        repository = IncidentLifecycleRepository(self.connection); repository.reconcile_cycle(1, [self.finding], self.events, observed_at=self.now, coverage_complete=True)
        changed = dict(self.finding); changed["finding_id"] = "fsf-b"; changed["severity"] = "critical"; changed["score"] = 98.0
        summary = repository.reconcile_cycle(2, [changed], self.events, observed_at=self.now + timedelta(minutes=1), coverage_complete=True)
        self.assertEqual(summary.changed, 1); incident = repository.recent_incidents(limit=1)[0]; self.assertEqual(incident["state"], "changed"); self.assertEqual(incident["incident"]["severity"], "critical")

    def test_incomplete_coverage_cannot_resolve_incident(self) -> None:
        repository = IncidentLifecycleRepository(self.connection); repository.reconcile_cycle(1, [self.finding], self.events, observed_at=self.now, coverage_complete=True)
        summary = repository.reconcile_cycle(2, [], [], observed_at=self.now + timedelta(minutes=5), coverage_complete=False)
        self.assertEqual(summary.resolved, 0); self.assertEqual(summary.active_total, 1); self.assertTrue(repository.recent_incidents(limit=1)[0]["active"])

    def test_complete_coverage_resolves_absent_incident(self) -> None:
        repository = IncidentLifecycleRepository(self.connection); repository.reconcile_cycle(1, [self.finding], self.events, observed_at=self.now, coverage_complete=True)
        summary = repository.reconcile_cycle(2, [], [], observed_at=self.now + timedelta(minutes=5), coverage_complete=True)
        self.assertEqual(summary.resolved, 1); self.assertEqual(summary.active_total, 0); incident = repository.recent_incidents(limit=1)[0]; self.assertEqual(incident["state"], "resolved"); self.assertFalse(incident["active"]); self.assertIsNotNone(incident["resolved_at"])

    def test_duplicate_cycle_is_idempotent(self) -> None:
        repository = IncidentLifecycleRepository(self.connection); repository.reconcile_cycle(1, [self.finding], self.events, observed_at=self.now, coverage_complete=True)
        duplicate = repository.reconcile_cycle(1, [self.finding], self.events, observed_at=self.now, coverage_complete=True)
        self.assertTrue(duplicate.already_processed); incident = repository.recent_incidents(limit=1)[0]; self.assertEqual(incident["cycles_seen"], 1); self.assertEqual(len(repository.recent_transitions()), 1)

    def test_cycle_gap_fails_closed(self) -> None:
        repository = IncidentLifecycleRepository(self.connection); repository.reconcile_cycle(1, [self.finding], self.events, observed_at=self.now, coverage_complete=True)
        with self.assertRaisesRegex(ValueError, "cycle gap"): repository.reconcile_cycle(3, [self.finding], self.events, observed_at=self.now + timedelta(minutes=2), coverage_complete=True)

    def test_catch_up_replays_signed_chain_without_auto_resolution(self) -> None:
        self.connection.execute("CREATE TABLE evidence_chain(cycle_id INTEGER PRIMARY KEY,payload_json TEXT NOT NULL)")
        first_payload = {"completed_at": "2026-08-07T20:00:00Z", "events": self.events, "report": {"findings": [self.finding]}}
        second_payload = {"completed_at": "2026-08-07T20:05:00Z", "events": [], "report": {"findings": []}}
        self.connection.executemany("INSERT INTO evidence_chain(cycle_id,payload_json) VALUES(?,?)", [(1, json.dumps(first_payload, sort_keys=True)), (2, json.dumps(second_payload, sort_keys=True))])
        repository = IncidentLifecycleRepository(self.connection); replayed = repository.catch_up_from_evidence_chain(); self.assertEqual(replayed, 2); self.assertEqual(repository.last_processed_cycle_id(), 2); incident = repository.recent_incidents(limit=1)[0]; self.assertTrue(incident["active"]); self.assertNotEqual(incident["state"], "resolved")

    def test_pruned_chain_bootstrap_records_history_floor(self) -> None:
        self.connection.execute("CREATE TABLE evidence_chain(cycle_id INTEGER PRIMARY KEY,payload_json TEXT NOT NULL)")
        payload = {"completed_at": "2026-08-07T20:00:00Z", "events": self.events, "report": {"findings": [self.finding]}}
        self.connection.execute("INSERT INTO evidence_chain(cycle_id,payload_json) VALUES(8,?)", (json.dumps(payload, sort_keys=True),))
        repository = IncidentLifecycleRepository(self.connection); self.assertEqual(repository.catch_up_from_evidence_chain(), 1); summary = repository.summary(); self.assertEqual(summary["history_floor_cycle_id"], 7); self.assertEqual(summary["last_processed_cycle_id"], 8)

    def test_transition_history_is_bounded(self) -> None:
        repository = IncidentLifecycleRepository(self.connection, max_transitions=2)
        for cycle_id in range(1, 5):
            finding = dict(self.finding); finding["finding_id"] = f"fsf-{cycle_id}"; repository.reconcile_cycle(cycle_id, [finding], self.events, observed_at=self.now + timedelta(minutes=cycle_id), coverage_complete=True)
        transitions = repository.recent_transitions(limit=100); self.assertEqual(len(transitions), 2); self.assertEqual([item["cycle_id"] for item in transitions], [4, 3]); self.assertEqual(repository.summary()["transitions"], 2)

    def test_old_resolved_incidents_are_bounded_and_counted(self) -> None:
        repository = IncidentLifecycleRepository(self.connection, max_resolved_incidents=1)
        first = dict(self.finding); second = dict(self.finding); second["finding_id"] = "fsf-second"; second["subject"] = "C:/Program Files/Example/second.exe"
        repository.reconcile_cycle(1, [first, second], self.events, observed_at=self.now, coverage_complete=True); repository.reconcile_cycle(2, [], [], observed_at=self.now + timedelta(minutes=5), coverage_complete=True)
        summary = repository.summary(); self.assertEqual(summary["incidents"], 1); self.assertEqual(summary["active"], 0); self.assertEqual(summary["pruned_resolved_incidents"], 1); self.assertEqual(summary["retention"]["max_resolved_incidents"], 1)


if __name__ == "__main__": unittest.main()
