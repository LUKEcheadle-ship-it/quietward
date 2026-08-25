from __future__ import annotations

import unittest

from quietward.cadence import CadenceController, CadenceLane
from quietward.maintenance_governor import AdaptiveMaintenanceGovernor


def metrics(*, cpu: float = 4.0, samples: int = 5) -> dict[str, object]:
    return {"profiles": {"fast": {"samples": samples, "phases_ms": {"total_before_health": {"p50": 200.0, "p95": 700.0}, "analysis": {"p95": 10.0}}, "context_metrics": {"process_cpu_percent_total_capacity": {"mean": cpu, "p50": cpu, "p95": cpu, "max": cpu}, "rss_mib": {"mean": 60.0, "p50": 60.0, "p95": 60.0, "max": 60.0}}}}}


class AdaptiveMaintenanceGovernorTests(unittest.TestCase):
    def controller(self, now: list[float]) -> CadenceController:
        controller = CadenceController(fast_seconds=60.0, standard_seconds=300.0, deep_seconds=300.0, maintenance_seconds=300.0, monotonic=lambda: now[0])
        controller.mark_completed(set(CadenceLane))
        return controller

    def test_attention_defers_only_optional_heavy_lanes_with_starvation_bound(self) -> None:
        now = [0.0]
        controller = self.controller(now)
        governor = AdaptiveMaintenanceGovernor(defer_seconds=60.0, max_consecutive_deferrals=2)
        now[0] = 300.0
        first = governor.apply(controller, metrics())
        self.assertEqual(set(first.deferred_lanes), {"deep", "maintenance"})
        self.assertEqual(set(controller.decision().due_lanes), {CadenceLane.FAST, CadenceLane.STANDARD})
        controller.mark_completed(controller.decision().due_lanes)
        now[0] = 360.0
        second = governor.apply(controller, metrics())
        self.assertEqual(set(second.deferred_lanes), {"deep", "maintenance"})
        self.assertEqual(controller.decision().due_lanes, (CadenceLane.FAST,))
        controller.mark_completed(controller.decision().due_lanes)
        now[0] = 420.0
        third = governor.apply(controller, metrics())
        self.assertEqual(third.deferred_lanes, ())
        due = set(controller.decision().due_lanes)
        self.assertIn(CadenceLane.DEEP, due)
        self.assertIn(CadenceLane.MAINTENANCE, due)
        self.assertIn(CadenceLane.FAST, due)

    def test_forced_security_request_overrides_deferral(self) -> None:
        now = [300.0]
        controller = self.controller(now)
        now[0] = 600.0
        controller.request({CadenceLane.MAINTENANCE})
        governor = AdaptiveMaintenanceGovernor()
        result = governor.apply(controller, metrics())
        self.assertNotIn("maintenance", result.deferred_lanes)
        self.assertIn("maintenance", result.forced_lanes)
        self.assertIn(CadenceLane.MAINTENANCE, controller.decision().due_lanes)

    def test_active_incident_lane_is_protected(self) -> None:
        now = [0.0]
        controller = self.controller(now)
        now[0] = 300.0
        governor = AdaptiveMaintenanceGovernor()
        result = governor.apply(controller, metrics(), protected_lanes={CadenceLane.DEEP})
        self.assertNotIn("deep", result.deferred_lanes)
        self.assertIn("deep", result.protected_lanes)
        self.assertIn(CadenceLane.DEEP, controller.decision().due_lanes)
        self.assertNotIn(CadenceLane.MAINTENANCE, controller.decision().due_lanes)

    def test_collecting_or_passing_budget_does_not_defer(self) -> None:
        now = [0.0]
        controller = self.controller(now)
        now[0] = 300.0
        governor = AdaptiveMaintenanceGovernor()
        collecting = governor.apply(controller, metrics(samples=2))
        self.assertEqual(collecting.performance_decision, "COLLECTING")
        self.assertEqual(collecting.deferred_lanes, ())
        passing = governor.apply(controller, metrics(cpu=1.0))
        self.assertEqual(passing.performance_decision, "PASS")
        self.assertEqual(passing.deferred_lanes, ())

    def test_fast_lane_cannot_be_deferred(self) -> None:
        now = [0.0]
        controller = self.controller(now)
        with self.assertRaisesRegex(ValueError, "fast cadence"):
            controller.defer({CadenceLane.FAST}, seconds=60.0)


if __name__ == "__main__":
    unittest.main()
