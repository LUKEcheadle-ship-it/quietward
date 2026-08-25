from __future__ import annotations

import unittest

from scripts.report_core_health import build_report


class CoreHealthReportTests(unittest.TestCase):
    def test_report_surfaces_fast_budget_resources_persistence_governor_restart_context_and_health_io(self) -> None:
        health = {
            "status": "healthy", "observed_at": "2026-08-08T02:00:00Z",
            "performance_budget": {"decision": "PASS", "fast_samples": 6, "actions_executed": 0},
            "performance": {"profiles": {"fast": {"samples": 6, "phases_ms": {"collector": {"p50": 80.0, "p95": 120.0}, "analysis": {"p95": 8.0}, "total_before_health": {"p50": 150.0, "p95": 250.0}}, "context_metrics": {"process_cpu_percent_total_capacity": {"mean": 0.8}, "rss_mib": {"max": 72.0}, "external_commands": {"mean": 1.0}, "external_command_ms": {"mean": 60.0}}}}, "latest_context": {"due_lanes": ["fast"], "persistence_mode": "volatile"}},
            "coverage": {"operationally_healthy": True, "resolution_safe": False, "degraded_required": 0, "scheduled_not_due": 3, "baseline": {"confidence": "established", "scanner_confidence": "unready"}},
            "cadence": {"forced_due": [], "restored_schedule": True}, "maintenance": {"last_persistence_mode": "volatile"},
            "adaptive_maintenance": {"performance_decision": "PASS", "deferred_lanes": [], "consecutive_deferrals": {"deep": 0, "maintenance": 0}, "actions_executed": 0},
            "warm_start": {"eligible": True, "reason": "recent_established_verified_baseline", "due_in_seconds": {"fast": 0.0, "standard": 60.0, "deep": 120.0, "maintenance": 180.0}, "actions_executed": 0},
            "temporal_context": {"retained_events": 42, "max_events": 512, "window_seconds": 300.0, "pending_events": 0, "actions_executed": 0},
            "health_write": {"mode": "live_atomic", "persistence_mode": "volatile", "checkpoint_seconds": 300.0, "seconds_since_durable": 60.0, "actions_executed": 0},
        }
        report = build_report(health)
        self.assertEqual(report["performance_budget"]["decision"], "PASS"); self.assertEqual(report["fast_profile"]["samples"], 6); self.assertEqual(report["fast_profile"]["process_cpu_percent_total_capacity"]["mean"], 0.8); self.assertEqual(report["fast_profile"]["rss_mib"]["max"], 72.0); self.assertEqual(report["latest_persistence_mode"], "volatile"); self.assertEqual(report["baseline"]["confidence"], "established"); self.assertEqual(report["baseline"]["scanner_confidence"], "unready"); self.assertEqual(report["adaptive_maintenance"]["performance_decision"], "PASS"); self.assertTrue(report["warm_start"]["eligible"]); self.assertTrue(report["cadence"]["restored_schedule"]); self.assertEqual(report["temporal_context"]["retained_events"], 42); self.assertEqual(report["temporal_context"]["max_events"], 512); self.assertEqual(report["health_write"]["mode"], "live_atomic"); self.assertEqual(report["health_write"]["persistence_mode"], "volatile"); self.assertEqual(report["safety"]["actions_executed"], 0)


if __name__ == "__main__": unittest.main()
