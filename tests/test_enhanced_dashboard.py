from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from quietward.config import StorageSettings
from quietward.enhanced_dashboard import QuietWardDashboardServer
from quietward.lifecycle_repository import IncidentLifecycleRepository
from quietward.storage import SentinelStore


class EnhancedDashboardTests(unittest.TestCase):
    def test_overview_includes_lifecycle_coverage_and_retention(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = StorageSettings(
                database_path=root / "sentinel.sqlite3",
                alert_log_path=root / "alerts.jsonl",
            )
            with SentinelStore(settings) as store:
                lifecycle = IncidentLifecycleRepository(store.connection)
                now = datetime(2026, 8, 7, 21, 0, tzinfo=timezone.utc)
                finding = {
                    "finding_id": "qwf-dashboard",
                    "host_id": "host-a",
                    "subject": "listener:127.0.0.1:4444",
                    "severity": "high",
                    "score": 82.0,
                    "evidence_event_ids": ["event-dashboard"],
                }
                events = [
                    {
                        "event_id": "event-dashboard",
                        "kind": "new_listening_port",
                        "source": "windows",
                        "observed_at": "2026-08-07T21:00:00Z",
                    }
                ]
                lifecycle.reconcile_cycle(
                    1,
                    [finding],
                    events,
                    observed_at=now,
                    coverage_complete=True,
                )
                coverage = {
                    "resolution_safe": False,
                    "degraded_count": 1,
                    "cycle_id": 1,
                    "observed_at": "2026-08-07T21:00:00Z",
                    "metadata_persisted": True,
                    "domains": [
                        {
                            "name": "processes",
                            "state": "degraded",
                            "required_for_resolution": True,
                            "resolution_complete": False,
                            "reason_code": "collector_error",
                            "issue_count": 1,
                        }
                    ],
                    "actions_executed": 0,
                }
                store.set_metadata(
                    "last_coverage_report",
                    json.dumps(coverage, sort_keys=True),
                )
                store.connection.commit()
                overview = QuietWardDashboardServer._overview(store, 100)

            self.assertEqual(overview["product"], "QuietWard")
            self.assertEqual(overview["dashboard_mode"], "read_only")
            self.assertEqual(overview["lifecycle"]["active"], 1)
            self.assertEqual(len(overview["incidents"]), 1)
            self.assertEqual(overview["incidents"][0]["state"], "new")
            self.assertEqual(len(overview["lifecycle_transitions"]), 1)
            self.assertFalse(overview["coverage"]["resolution_safe"])
            self.assertEqual(overview["coverage"]["cycle_id"], 1)
            self.assertEqual(
                overview["coverage"]["domains"][0]["name"],
                "processes",
            )
            self.assertTrue(overview["retention"]["bounded"])
            capacity_names = {
                item["name"] for item in overview["retention"]["capacities"]
            }
            self.assertEqual(
                capacity_names,
                {"cycles", "snapshots", "events", "findings", "scanner_runs"},
            )
            self.assertEqual(overview["retention"]["actions_executed"], 0)
            self.assertEqual(overview["actions_executed"], 0)

    def test_invalid_stored_coverage_degrades_to_none(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = StorageSettings(
                database_path=root / "sentinel.sqlite3",
                alert_log_path=root / "alerts.jsonl",
            )
            with SentinelStore(settings) as store:
                store.set_metadata("last_coverage_report", "not-json")
                store.connection.commit()
                self.assertIsNone(QuietWardDashboardServer._coverage(store))

    def test_visual_dashboard_is_quietward_and_observation_only(self) -> None:
        html = QuietWardDashboardServer._html()
        self.assertIn("<title>QuietWard</title>", html)
        self.assertIn("Incident lifecycle", html)
        self.assertIn("Monitoring coverage", html)
        self.assertIn("Bounded local retention", html)
        self.assertIn("Actions executed", html)
        self.assertIn("Observation only.", html)
        self.assertIn("/api/overview?limit=100", html)
        self.assertNotIn("Forge" + " Sentinel", html)
        self.assertNotIn("fetch('http", html)
        self.assertNotIn("fetch(\"http", html)
        self.assertNotIn("POST", html)
        self.assertNotIn("DELETE", html)
        self.assertNotIn(
            "quarantine",
            html.casefold().replace("does not quarantine", ""),
        )


if __name__ == "__main__":
    unittest.main()
