from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from quietward.finding_lifecycle import LifecycleState, build_incident_identity, observe_incident, resolve_absent_incidents


class FindingLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 8, 7, 18, 0, tzinfo=timezone.utc)
        self.finding = {"finding_id": "qwf-a", "host_id": "host-a", "subject": "C:/Program Files/Example/example.exe", "severity": "high", "score": 82.0, "evidence_event_ids": ["event-a", "event-b"]}
        self.events = [
            {"event_id": "event-a", "kind": "new_listening_port", "source": "windows", "observed_at": "2026-08-07T18:00:00Z"},
            {"event_id": "event-b", "kind": "persistence_change", "source": "windows", "observed_at": "2026-08-07T18:00:00Z"},
        ]

    def test_identity_is_stable_across_event_ids_order_and_timestamps(self) -> None:
        first = build_incident_identity(self.finding, self.events)
        second_finding = dict(self.finding)
        second_finding["finding_id"] = "qwf-b"
        second_finding["evidence_event_ids"] = ["event-d", "event-c"]
        second_events = [
            {"event_id": "event-c", "kind": "persistence_change", "source": "windows", "observed_at": "2026-08-07T19:00:00Z"},
            {"event_id": "event-d", "kind": "new_listening_port", "source": "windows", "observed_at": "2026-08-07T19:00:00Z"},
        ]
        second = build_incident_identity(second_finding, second_events)
        self.assertEqual(first.incident_key, second.incident_key)
        self.assertEqual(first.signature, second.signature)
        self.assertNotEqual(first.finding_id, second.finding_id)

    def test_material_evidence_change_is_classified_as_changed(self) -> None:
        first_identity = build_incident_identity(self.finding, self.events)
        first = observe_incident(None, first_identity, observed_at=self.now)
        changed_finding = dict(self.finding)
        changed_finding["finding_id"] = "qwf-b"
        changed_finding["severity"] = "critical"
        changed_finding["score"] = 96.0
        second = observe_incident(first, build_incident_identity(changed_finding, self.events), observed_at=self.now + timedelta(minutes=1))
        self.assertEqual(second.state, LifecycleState.CHANGED)
        self.assertEqual(second.cycles_seen, 2)
        self.assertEqual(second.occurrences, 2)
        self.assertTrue(second.active)

    def test_same_incident_becomes_recurring_without_duplicate_occurrence(self) -> None:
        identity = build_incident_identity(self.finding, self.events)
        first = observe_incident(None, identity, observed_at=self.now)
        second = observe_incident(first, identity, observed_at=self.now + timedelta(minutes=1))
        self.assertEqual(second.state, LifecycleState.RECURRING)
        self.assertEqual(second.cycles_seen, 2)
        self.assertEqual(second.occurrences, 1)

    def test_incomplete_coverage_never_resolves_from_absence(self) -> None:
        identity = build_incident_identity(self.finding, self.events)
        record = observe_incident(None, identity, observed_at=self.now)
        result = resolve_absent_incidents({identity.incident_key: record}, (), completed_at=self.now + timedelta(minutes=5), coverage_complete=False)
        self.assertEqual(result[identity.incident_key].state, LifecycleState.NEW)
        self.assertTrue(result[identity.incident_key].active)
        self.assertIsNone(result[identity.incident_key].resolved_at)

    def test_complete_coverage_resolves_and_reappearance_recurs(self) -> None:
        identity = build_incident_identity(self.finding, self.events)
        first = observe_incident(None, identity, observed_at=self.now)
        resolved = resolve_absent_incidents({identity.incident_key: first}, (), completed_at=self.now + timedelta(minutes=5), coverage_complete=True)[identity.incident_key]
        self.assertEqual(resolved.state, LifecycleState.RESOLVED)
        self.assertFalse(resolved.active)
        reappeared_finding = dict(self.finding)
        reappeared_finding["finding_id"] = "qwf-c"
        reappeared = observe_incident(resolved, build_incident_identity(reappeared_finding, self.events), observed_at=self.now + timedelta(minutes=10))
        self.assertEqual(reappeared.state, LifecycleState.RECURRING)
        self.assertTrue(reappeared.active)
        self.assertIsNone(reappeared.resolved_at)
        self.assertEqual(reappeared.occurrences, 2)

    def test_naive_timestamps_are_rejected(self) -> None:
        identity = build_incident_identity(self.finding, self.events)
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            observe_incident(None, identity, observed_at=datetime(2026, 8, 7, 18, 0))


if __name__ == "__main__":
    unittest.main()
