from __future__ import annotations

import unittest

from quietward.runtime_metrics import RuntimeMetrics


class RuntimeMetricsTests(unittest.TestCase):
    def test_window_is_bounded_and_reports_percentiles(self) -> None:
        metrics = RuntimeMetrics(max_samples=3)
        for value in (10.0, 20.0, 30.0, 40.0):
            metrics.record({"collector": value, "total_before_health": value + 5.0}, context={"external_commands": 1})
        summary = metrics.summary()
        self.assertEqual(summary["samples"], 3)
        self.assertEqual(summary["capacity"], 3)
        self.assertEqual(summary["phases_ms"]["collector"]["mean"], 30.0)
        self.assertEqual(summary["phases_ms"]["collector"]["max"], 40.0)
        self.assertEqual(summary["context_metrics"]["external_commands"]["mean"], 1.0)
        self.assertEqual(summary["latest_context"]["external_commands"], 1)
        self.assertEqual(summary["actions_executed"], 0)

    def test_profiles_keep_fast_cycles_separate_from_maintenance(self) -> None:
        metrics = RuntimeMetrics(max_samples=10)
        for latency, cpu, rss in ((100.0, 0.5, 60.0), (120.0, 0.7, 61.0), (140.0, 0.6, 62.0)):
            metrics.record({"analysis": 5.0, "total_before_health": latency}, context={"due_lanes": ["fast"], "process_cpu_percent_total_capacity": cpu, "rss_mib": rss, "persistence_mode": "volatile"})
        metrics.record({"analysis": 8.0, "total_before_health": 3000.0}, context={"due_lanes": ["fast", "maintenance"], "process_cpu_percent_total_capacity": 4.0, "rss_mib": 70.0, "persistence_mode": "full"})
        summary = metrics.summary()
        fast = summary["profiles"]["fast"]
        maintenance = summary["profiles"]["fast+maintenance"]
        self.assertEqual(fast["samples"], 3)
        self.assertEqual(maintenance["samples"], 1)
        self.assertEqual(fast["phases_ms"]["total_before_health"]["max"], 140.0)
        self.assertEqual(fast["context_metrics"]["process_cpu_percent_total_capacity"]["max"], 0.7)
        self.assertEqual(fast["context_metrics"]["rss_mib"]["max"], 62.0)
        self.assertNotIn("persistence_mode", fast["context_metrics"])
        self.assertEqual(fast["latest_context"]["persistence_mode"], "volatile")

    def test_health_phase_can_amend_latest_sample_without_adding_one(self) -> None:
        metrics = RuntimeMetrics(max_samples=5)
        metrics.record({"collector": 12.5}, context={"due_lanes": ["fast"]})
        metrics.amend_latest("health", 3.25)
        summary = metrics.summary()
        self.assertEqual(summary["samples"], 1)
        self.assertEqual(summary["latest_ms"]["health"], 3.25)
        self.assertEqual(summary["latest_context"]["due_lanes"], ["fast"])
        self.assertEqual(summary["profiles"]["fast"]["phases_ms"]["health"]["max"], 3.25)


if __name__ == "__main__":
    unittest.main()
