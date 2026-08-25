from __future__ import annotations

import unittest

from quietward.performance_budget import evaluate_performance_budget
from quietward.runtime_metrics import RuntimeMetrics


class PerformanceBudgetTests(unittest.TestCase):
    def metrics(
        self,
        *,
        samples: int = 5,
        cpu: float = 1.0,
        rss: float = 80.0,
        p50: float = 200.0,
        p95: float = 700.0,
        analysis: float = 10.0,
    ):
        return {
            "profiles": {
                "fast": {
                    "samples": samples,
                    "phases_ms": {
                        "total_before_health": {
                            "p50": p50,
                            "p95": p95,
                        },
                        "analysis": {"p95": analysis},
                    },
                    "context_metrics": {
                        "process_cpu_percent_total_capacity": {"mean": cpu},
                        "rss_mib": {"max": rss},
                    },
                },
                "fast+maintenance": {
                    "samples": 1,
                    "phases_ms": {
                        "total_before_health": {"p50": 5000.0, "p95": 5000.0},
                        "analysis": {"p95": 10.0},
                    },
                    "context_metrics": {},
                },
            }
        }

    def test_pass_uses_fast_profile_not_maintenance_spike(self) -> None:
        result = evaluate_performance_budget(self.metrics())
        self.assertEqual(result["decision"], "PASS")
        self.assertTrue(all(item["pass"] for item in result["checks"]))
        self.assertEqual(result["actions_executed"], 0)

    def test_runtime_metrics_summary_drives_real_budget_decision(self) -> None:
        metrics = RuntimeMetrics(max_samples=10)
        for latency in (120.0, 150.0, 180.0, 200.0, 220.0):
            metrics.record(
                {
                    "analysis": 8.0,
                    "total_before_health": latency,
                },
                context={
                    "due_lanes": ["fast"],
                    "process_cpu_percent_total_capacity": 0.9,
                    "rss_mib": 70.0,
                    "persistence_mode": "volatile",
                },
            )
        metrics.record(
            {"analysis": 10.0, "total_before_health": 4000.0},
            context={
                "due_lanes": ["fast", "maintenance"],
                "process_cpu_percent_total_capacity": 5.0,
                "rss_mib": 85.0,
                "persistence_mode": "full",
            },
        )
        result = evaluate_performance_budget(metrics.summary())
        self.assertEqual(result["decision"], "PASS")
        self.assertEqual(result["fast_samples"], 5)
        self.assertTrue(all(item["pass"] for item in result["checks"]))

    def test_collecting_until_enough_fast_samples_exist(self) -> None:
        result = evaluate_performance_budget(self.metrics(samples=2))
        self.assertEqual(result["decision"], "COLLECTING")
        self.assertEqual(result["fast_samples"], 2)

    def test_attention_identifies_failed_budgets(self) -> None:
        result = evaluate_performance_budget(
            self.metrics(cpu=4.0, rss=140.0, p95=2200.0)
        )
        self.assertEqual(result["decision"], "ATTENTION")
        failed = {item["name"] for item in result["checks"] if not item["pass"]}
        self.assertEqual(
            failed,
            {"idle_cpu_mean", "rss_max", "fast_cycle_p95"},
        )

    def test_missing_fast_profile_stays_collecting(self) -> None:
        result = evaluate_performance_budget({"profiles": {}})
        self.assertEqual(result["decision"], "COLLECTING")
        self.assertEqual(result["fast_samples"], 0)


if __name__ == "__main__":
    unittest.main()
