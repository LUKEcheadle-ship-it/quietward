from __future__ import annotations

import unittest
from pathlib import Path

from quietward.config import StorageSettings
from quietward.retention_health import assess_retention_health


class RetentionHealthTests(unittest.TestCase):
    def settings(self) -> StorageSettings:
        return StorageSettings(
            database_path=Path("/tmp/quietward-test.sqlite3"),
            alert_log_path=Path("/tmp/quietward-alerts.jsonl"),
            max_snapshots=20, max_events=100, max_findings=40,
            retention_days=30, max_cycles=10, max_scanner_runs=50,
        )

    def test_reports_utilization_without_host_paths(self) -> None:
        result = assess_retention_health(self.settings(), {"cycles": 5, "snapshots": 10, "events": 25, "findings": 4, "scanner_runs": 0}).to_dict()
        self.assertTrue(result["bounded"])
        capacities = {item["name"]: item for item in result["capacities"]}
        self.assertEqual(capacities["cycles"]["utilization"], 0.5)
        self.assertEqual(capacities["events"]["utilization"], 0.25)
        self.assertEqual(result["caps_reached"], [])
        self.assertNotIn("quietward-test.sqlite3", str(result))
        self.assertEqual(result["actions_executed"], 0)

    def test_reaching_retention_cap_is_explicit(self) -> None:
        result = assess_retention_health(self.settings(), {"cycles": 10, "snapshots": 20, "events": 100, "findings": 39, "scanner_runs": 50}).to_dict()
        self.assertEqual(result["caps_reached"], ["cycles", "snapshots", "events", "scanner_runs"])
        capacities = {item["name"]: item for item in result["capacities"]}
        self.assertTrue(capacities["events"]["at_limit"])
        self.assertFalse(capacities["findings"]["at_limit"])

    def test_counts_above_limit_are_safely_clamped_for_reporting(self) -> None:
        result = assess_retention_health(self.settings(), {"cycles": 999, "snapshots": 0, "events": 0, "findings": 0, "scanner_runs": 0}).to_dict()
        cycles = next(item for item in result["capacities"] if item["name"] == "cycles")
        self.assertEqual(cycles["utilization"], 1.0)
        self.assertTrue(cycles["at_limit"])


if __name__ == "__main__":
    unittest.main()
