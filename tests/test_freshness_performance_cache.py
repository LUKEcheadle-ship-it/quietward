from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quietward.config import ScannerJobSettings
from quietward.freshness import ScannerFreshnessInspector


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class CountingInspector(ScannerFreshnessInspector):
    def __init__(self, *args, candidate: Path, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.candidate = candidate
        self.discovery_calls = 0

    def _candidate_files(self, job):
        self.discovery_calls += 1
        return [self.candidate]


class FreshnessPerformanceCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        ScannerFreshnessInspector.clear_cache()

    def test_reuses_discovery_then_rescans_after_cache_window(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rules = root / "rules.yar"
            rules.write_text("rule Example { condition: true }", encoding="utf-8")
            start = datetime(2026, 8, 7, 20, 0, tzinfo=timezone.utc)
            stamp = (start - timedelta(minutes=10)).timestamp()
            os.utime(rules, (stamp, stamp))
            clock = MutableClock(start)
            inspector = CountingInspector(
                now=clock,
                discovery_cache_seconds=300,
                candidate=rules,
            )
            job = ScannerJobSettings(
                scanner="yara",
                enabled=True,
                interval_seconds=60.0,
                timeout_seconds=30.0,
                rules_path=rules,
                max_data_age_hours=1.0,
            )

            first = inspector.inspect(job)
            self.assertFalse(first.stale)
            self.assertEqual(inspector.discovery_calls, 1)

            clock.value = start + timedelta(minutes=1)
            second = inspector.inspect(job)
            self.assertFalse(second.stale)
            self.assertEqual(inspector.discovery_calls, 1)
            self.assertGreater(second.age_hours, first.age_hours)

            clock.value = start + timedelta(minutes=6)
            inspector.inspect(job)
            self.assertEqual(inspector.discovery_calls, 2)

    def test_stale_threshold_can_cross_without_directory_rescan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rules = root / "rules.yar"
            rules.write_text("rule Example { condition: true }", encoding="utf-8")
            start = datetime(2026, 8, 7, 20, 0, tzinfo=timezone.utc)
            stamp = (start - timedelta(minutes=59)).timestamp()
            os.utime(rules, (stamp, stamp))
            clock = MutableClock(start)
            inspector = CountingInspector(
                now=clock,
                discovery_cache_seconds=300,
                candidate=rules,
            )
            job = ScannerJobSettings(
                scanner="yara",
                enabled=True,
                interval_seconds=60.0,
                timeout_seconds=30.0,
                rules_path=rules,
                max_data_age_hours=1.0,
            )

            self.assertFalse(inspector.inspect(job).stale)
            clock.value = start + timedelta(minutes=2)
            second = inspector.inspect(job)
            self.assertTrue(second.stale)
            self.assertEqual(inspector.discovery_calls, 1)

    def test_identical_stale_event_is_not_reemitted_each_fast_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rules = root / "rules.yar"
            rules.write_text("rule Example { condition: true }", encoding="utf-8")
            start = datetime(2026, 8, 7, 20, 0, tzinfo=timezone.utc)
            stamp = (start - timedelta(hours=2)).timestamp()
            os.utime(rules, (stamp, stamp))
            clock = MutableClock(start)
            inspector = CountingInspector(
                now=clock,
                discovery_cache_seconds=300,
                event_repeat_seconds=300,
                candidate=rules,
            )
            job = ScannerJobSettings(
                scanner="yara",
                enabled=True,
                interval_seconds=60.0,
                timeout_seconds=30.0,
                rules_path=rules,
                max_data_age_hours=1.0,
            )

            first = inspector.event(job, "host-a")
            self.assertIsNotNone(first)
            clock.value = start + timedelta(minutes=1)
            self.assertIsNone(inspector.event(job, "host-a"))
            clock.value = start + timedelta(minutes=5)
            repeated = inspector.event(job, "host-a")
            self.assertIsNotNone(repeated)
            self.assertEqual(first.event_id, repeated.event_id)


if __name__ == "__main__":
    unittest.main()
