from __future__ import annotations

import importlib
import unittest

from quietward import __version__
from quietward.performance_budget import evaluate_performance_budget
from quietward.runtime import bundled_model_path


CORE_MODULES = (
    "quietward.baseline",
    "quietward.cadence",
    "quietward.cadenced_collector",
    "quietward.cadenced_service",
    "quietward.contextual_pipeline",
    "quietward.core_service",
    "quietward.core_store",
    "quietward.coverage",
    "quietward.dashboard_performance",
    "quietward.enhanced_dashboard",
    "quietward.finding_lifecycle",
    "quietward.health_io",
    "quietward.incident_coverage",
    "quietward.lifecycle_repository",
    "quietward.maintenance_governor",
    "quietward.maintenance_store",
    "quietward.operational_findings",
    "quietward.performance_budget",
    "quietward.performance_service",
    "quietward.performance_store",
    "quietward.process_metrics",
    "quietward.product_store",
    "quietward.retention_health",
    "quietward.runtime_metrics",
    "quietward.source_aware_lifecycle",
    "quietward.support_context",
    "quietward.temporal_context",
    "quietward.user_status",
    "quietward.warm_start",
    "quietward.windows_trust",
    "quietward.collectors.docker_batch",
    "quietward.collectors.windows_attribution",
    "quietward.collectors.windows_core",
    "quietward.collectors.windows_fast_core_command",
    "quietward.collectors.windows_native_fast",
)


class V05CoreModuleSmokeTests(unittest.TestCase):
    def test_all_combined_core_modules_import(self) -> None:
        for name in CORE_MODULES:
            with self.subTest(module=name):
                self.assertIsNotNone(importlib.import_module(name))

    def test_release_version_and_bundled_model_match(self) -> None:
        self.assertEqual(__version__, "0.6.0a1")
        model = bundled_model_path()
        self.assertTrue(model.is_file(), model)
        self.assertEqual(model.name, "quietward_priority_tiny_v1.json")

    def test_performance_budget_contract_accepts_approved_shape(self) -> None:
        metrics = {
            "profiles": {
                "fast": {
                    "samples": 5,
                    "phases_ms": {
                        "total_before_health": {"p50": 100.0, "p95": 150.0},
                        "analysis": {"p95": 1.0},
                    },
                    "context_metrics": {
                        "process_cpu_percent_total_capacity": {"mean": 0.1},
                        "rss_mib": {"max": 40.0},
                    },
                }
            }
        }
        result = evaluate_performance_budget(metrics)
        self.assertEqual(result["decision"], "PASS")
        self.assertEqual(result["actions_executed"], 0)


if __name__ == "__main__":
    unittest.main()
