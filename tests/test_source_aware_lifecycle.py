from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from quietward.lifecycle_repository import IncidentLifecycleRepository
from quietward.source_aware_lifecycle import SourceAwareIncidentLifecycleRepository


class SourceAwareLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.repository = SourceAwareIncidentLifecycleRepository(self.connection)
        self.now = datetime(2026, 8, 7, 23, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.connection.close()

    def finding(self, finding_id: str, event_id: str):
        return {
            "finding_id": finding_id,
            "host_id": "host-a",
            "subject": "listener:*:4444",
            "severity": "high",
            "score": 80.0,
            "evidence_event_ids": [event_id],
        }

    def event(self, event_id: str, source: str):
        return {
            "event_id": event_id,
            "source": source,
            "kind": "new_listening_port",
            "observed_at": "2026-08-07T23:00:00Z",
        }

    def test_unrelated_scanner_not_due_does_not_block_listener_resolution(self) -> None:
        self.repository.reconcile_cycle(
            1,
            [self.finding("f1", "e1")],
            [self.event("e1", "windows_socket_snapshot")],
            observed_at=self.now,
            coverage_complete=False,
            coverage_domains=[
                {"name": "listening_sockets", "state": "complete"},
                {"name": "scanner:clamav:0", "state": "not_due"},
            ],
        )
        second = self.repository.reconcile_cycle(
            2,
            [],
            [],
            observed_at=self.now + timedelta(minutes=1),
            coverage_complete=False,
            coverage_domains=[
                {"name": "listening_sockets", "state": "complete"},
                {"name": "scanner:clamav:0", "state": "not_due"},
            ],
        )
        self.assertEqual(second.resolved, 1)
        self.assertEqual(second.active_total, 0)
        self.assertEqual(self.repository.recent_incidents(limit=1)[0]["state"], "resolved")

    def test_scanner_incident_waits_for_scanner_completion(self) -> None:
        finding = {
            "finding_id": "f1",
            "host_id": "host-a",
            "subject": "artifact-hash",
            "severity": "critical",
            "score": 95.0,
            "evidence_event_ids": ["e1"],
        }
        event = {
            "event_id": "e1",
            "source": "clamav",
            "kind": "malware_signature",
            "observed_at": "2026-08-07T23:00:00Z",
        }
        self.repository.reconcile_cycle(
            1,
            [finding],
            [event],
            observed_at=self.now,
            coverage_complete=True,
            coverage_domains=[{"name": "scanner:clamav:0", "state": "complete"}],
        )
        blocked = self.repository.reconcile_cycle(
            2,
            [],
            [],
            observed_at=self.now + timedelta(minutes=1),
            coverage_complete=False,
            coverage_domains=[{"name": "scanner:clamav:0", "state": "not_due"}],
        )
        self.assertEqual(blocked.resolved, 0)
        self.assertEqual(blocked.active_total, 1)

        resolved = self.repository.reconcile_cycle(
            3,
            [],
            [],
            observed_at=self.now + timedelta(minutes=2),
            coverage_complete=True,
            coverage_domains=[{"name": "scanner:clamav:0", "state": "complete"}],
        )
        self.assertEqual(resolved.resolved, 1)
        self.assertEqual(resolved.active_total, 0)

    def test_disabling_relevant_domain_does_not_clear_incident(self) -> None:
        finding = {
            "finding_id": "f1",
            "host_id": "host-a",
            "subject": "persistence-entry",
            "severity": "high",
            "score": 75.0,
            "evidence_event_ids": ["e1"],
        }
        event = {
            "event_id": "e1",
            "source": "windows_persistence_snapshot",
            "kind": "persistence_change",
            "observed_at": "2026-08-07T23:00:00Z",
        }
        self.repository.reconcile_cycle(
            1,
            [finding],
            [event],
            observed_at=self.now,
            coverage_complete=True,
            coverage_domains=[{"name": "persistence", "state": "complete"}],
        )
        second = self.repository.reconcile_cycle(
            2,
            [],
            [],
            observed_at=self.now + timedelta(minutes=1),
            coverage_complete=True,
            coverage_domains=[{"name": "persistence", "state": "disabled"}],
        )
        self.assertEqual(second.resolved, 0)
        self.assertEqual(second.active_total, 1)

    def test_no_domain_data_preserves_legacy_conservative_behavior(self) -> None:
        self.repository.reconcile_cycle(
            1,
            [self.finding("f1", "e1")],
            [self.event("e1", "windows_socket_snapshot")],
            observed_at=self.now,
            coverage_complete=True,
        )
        second = self.repository.reconcile_cycle(
            2,
            [],
            [],
            observed_at=self.now + timedelta(minutes=1),
            coverage_complete=False,
        )
        self.assertEqual(second.resolved, 0)
        self.assertEqual(second.active_total, 1)

    def test_reappearing_resolved_incident_does_not_require_full_history_load(self) -> None:
        domains = [{"name": "listening_sockets", "state": "complete"}]
        self.repository.reconcile_cycle(
            1,
            [self.finding("f1", "e1")],
            [self.event("e1", "windows_socket_snapshot")],
            observed_at=self.now,
            coverage_complete=True,
            coverage_domains=domains,
        )
        self.repository.reconcile_cycle(
            2,
            [],
            [],
            observed_at=self.now + timedelta(minutes=1),
            coverage_complete=True,
            coverage_domains=domains,
        )

        with mock.patch.object(
            self.repository,
            "load_records",
            side_effect=AssertionError("full lifecycle history should not load"),
        ):
            result = self.repository.reconcile_cycle(
                3,
                [self.finding("f2", "e2")],
                [self.event("e2", "windows_socket_snapshot")],
                observed_at=self.now + timedelta(minutes=2),
                coverage_complete=True,
                coverage_domains=domains,
            )
        self.assertEqual(result.recurring, 1)
        self.assertEqual(result.active_total, 1)

    def test_current_lifecycle_skips_evidence_catch_up_query(self) -> None:
        self.repository._set_meta("last_processed_cycle_id", "10")
        with mock.patch.object(
            IncidentLifecycleRepository,
            "catch_up_from_evidence_chain",
            side_effect=AssertionError("evidence catch-up query should not run"),
        ):
            self.assertEqual(
                self.repository.catch_up_from_evidence_chain(up_to_cycle_id=10),
                0,
            )


if __name__ == "__main__":
    unittest.main()
