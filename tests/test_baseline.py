from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone

from quietward.baseline import CoverageBaselineTracker


class CoverageBaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 8, 8, 5, 0, tzinfo=timezone.utc)
        self.complete = [
            {"name": "processes", "state": "complete", "required_for_resolution": True},
            {"name": "persistence", "state": "complete", "required_for_resolution": True},
            {"name": "microsoft_defender", "state": "degraded", "required_for_resolution": False},
        ]

    def test_first_complete_baseline_is_ready_but_not_established(self) -> None:
        tracker = CoverageBaselineTracker()
        value = tracker.observe(self.complete, observed_at=self.now)
        self.assertTrue(value["ready"])
        self.assertFalse(value["established"])
        self.assertEqual(value["confidence"], "initial")
        required = {item["name"]: item for item in value["domains"]}
        self.assertEqual(required["processes"]["complete_observations"], 1)
        self.assertEqual(required["persistence"]["complete_observations"], 1)
        self.assertTrue(required["processes"]["baseline_required"])

    def test_scheduled_skip_does_not_erase_or_inflate_confidence(self) -> None:
        tracker = CoverageBaselineTracker()
        tracker.observe(self.complete, observed_at=self.now)
        value = tracker.observe([
            {"name": "processes", "state": "complete", "required_for_resolution": True},
            {"name": "persistence", "state": "not_due", "required_for_resolution": True},
        ], observed_at=self.now + timedelta(minutes=1))
        self.assertTrue(value["ready"])
        persistence = next(item for item in value["domains"] if item["name"] == "persistence")
        self.assertEqual(persistence["complete_observations"], 1)
        self.assertEqual(persistence["scheduled_skips"], 1)

    def test_three_complete_observations_establish_required_baseline(self) -> None:
        tracker = CoverageBaselineTracker()
        value = None
        for index in range(3):
            value = tracker.observe(self.complete, observed_at=self.now + timedelta(minutes=5 * index))
        assert value is not None
        self.assertTrue(value["ready"])
        self.assertTrue(value["established"])
        self.assertEqual(value["confidence"], "established")

    def test_long_interval_scanner_does_not_block_core_establishment(self) -> None:
        tracker = CoverageBaselineTracker()
        value = None
        for index in range(3):
            value = tracker.observe([*self.complete, {"name": "scanner:clamav:0", "state": "not_due", "required_for_resolution": True}], observed_at=self.now + timedelta(minutes=5 * index))
        assert value is not None
        self.assertTrue(value["established"])
        self.assertEqual(value["confidence"], "established")
        self.assertEqual(value["scanner_domains"], 1)
        self.assertFalse(value["scanner_ready"])
        self.assertFalse(value["scanner_established"])
        self.assertEqual(value["scanner_confidence"], "unready")
        scanner = next(item for item in value["domains"] if item["name"] == "scanner:clamav:0")
        self.assertFalse(scanner["baseline_required"])
        self.assertEqual(scanner["scheduled_skips"], 3)

    def test_scanner_maturity_advances_independently_when_it_runs(self) -> None:
        tracker = CoverageBaselineTracker()
        value = None
        for index in range(3):
            value = tracker.observe([*self.complete, {"name": "scanner:yara:0", "state": "complete", "required_for_resolution": True}], observed_at=self.now + timedelta(hours=index))
        assert value is not None
        self.assertTrue(value["established"])
        self.assertTrue(value["scanner_ready"])
        self.assertTrue(value["scanner_established"])
        self.assertEqual(value["scanner_confidence"], "established")

    def test_degraded_required_domain_does_not_make_baseline_ready(self) -> None:
        tracker = CoverageBaselineTracker()
        value = tracker.observe([
            {"name": "processes", "state": "complete", "required_for_resolution": True},
            {"name": "persistence", "state": "degraded", "required_for_resolution": True},
        ], observed_at=self.now)
        self.assertFalse(value["ready"])
        self.assertEqual(value["confidence"], "unready")

    def test_tracker_recovers_from_existing_coverage_metadata(self) -> None:
        first = CoverageBaselineTracker()
        baseline = first.observe(self.complete, observed_at=self.now)
        restored = CoverageBaselineTracker.from_coverage_metadata(json.dumps({"baseline": baseline}))
        value = restored.observe(self.complete, observed_at=self.now + timedelta(minutes=5))
        processes = next(item for item in value["domains"] if item["name"] == "processes")
        self.assertEqual(processes["complete_observations"], 2)
        self.assertTrue(value["ready"])

    def test_older_metadata_without_baseline_required_is_migrated_in_memory(self) -> None:
        legacy = {"baseline": {"domains": [
            {"name": "processes", "required_for_resolution": True, "complete_observations": 3, "degraded_observations": 0, "scheduled_skips": 0, "first_complete_at": self.now.isoformat(), "last_complete_at": self.now.isoformat(), "last_state": "complete"},
            {"name": "scanner:clamav:0", "required_for_resolution": True, "complete_observations": 0, "degraded_observations": 0, "scheduled_skips": 2, "first_complete_at": None, "last_complete_at": None, "last_state": "not_due"},
        ]}}
        tracker = CoverageBaselineTracker.from_coverage_metadata(json.dumps(legacy))
        value = tracker.summary()
        self.assertTrue(value["established"])
        scanner = next(item for item in value["domains"] if item["name"] == "scanner:clamav:0")
        self.assertFalse(scanner["baseline_required"])

    def test_naive_timestamp_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            CoverageBaselineTracker().observe(self.complete, observed_at=datetime(2026, 8, 8, 5, 0))


if __name__ == "__main__":
    unittest.main()
