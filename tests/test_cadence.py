from __future__ import annotations

import unittest

from quietward.cadence import (
    CadenceController,
    CadenceLane,
    apply_collector_cadence,
    cadence_counts,
    operationally_healthy,
)
from quietward.coverage import complete_domain, domain, degraded_domain


class CadenceTests(unittest.TestCase):
    def test_scheduler_runs_all_lanes_first_then_due_lanes_only(self) -> None:
        now = [0.0]
        controller = CadenceController(
            fast_seconds=60.0,
            standard_seconds=300.0,
            deep_seconds=900.0,
            maintenance_seconds=300.0,
            monotonic=lambda: now[0],
        )
        first = controller.decision()
        self.assertTrue(first.first_cycle)
        self.assertEqual(set(first.due_lanes), set(CadenceLane))
        controller.mark_completed(first.due_lanes)

        now[0] = 60.0
        second = controller.decision()
        self.assertEqual(second.due_lanes, (CadenceLane.FAST,))
        self.assertEqual(
            second.collector_domains,
            frozenset(
                {
                    "processes",
                    "listening_sockets",
                    "outbound_connections",
                    "authentication",
                }
            ),
        )
        controller.mark_completed(second.due_lanes)

        now[0] = 300.0
        third = controller.decision()
        self.assertEqual(
            set(third.due_lanes),
            {CadenceLane.FAST, CadenceLane.STANDARD, CadenceLane.MAINTENANCE},
        )
        controller.mark_completed(third.due_lanes)

        now[0] = 900.0
        fourth = controller.decision()
        self.assertIn(CadenceLane.DEEP, fourth.due_lanes)
        self.assertIn(CadenceLane.FAST, fourth.due_lanes)

    def test_phase_offsets_stagger_heavy_lanes_after_first_baseline(self) -> None:
        now = [0.0]
        controller = CadenceController(
            fast_seconds=60.0,
            standard_seconds=300.0,
            deep_seconds=300.0,
            maintenance_seconds=300.0,
            phase_offsets_seconds={
                CadenceLane.STANDARD: 60.0,
                CadenceLane.DEEP: 120.0,
                CadenceLane.MAINTENANCE: 180.0,
            },
            monotonic=lambda: now[0],
        )
        first = controller.decision()
        controller.mark_completed(first.due_lanes)
        state = controller.state()
        self.assertEqual(state["seconds_until_due"]["standard"], 360.0)
        self.assertEqual(state["seconds_until_due"]["deep"], 420.0)
        self.assertEqual(state["seconds_until_due"]["maintenance"], 480.0)

        now[0] = 300.0
        self.assertEqual(controller.decision().due_lanes, (CadenceLane.FAST,))
        now[0] = 360.0
        self.assertEqual(
            set(controller.decision().due_lanes),
            {CadenceLane.FAST, CadenceLane.STANDARD},
        )
        now[0] = 420.0
        self.assertIn(CadenceLane.DEEP, controller.decision().due_lanes)
        self.assertNotIn(CadenceLane.MAINTENANCE, controller.decision().due_lanes)
        now[0] = 480.0
        self.assertIn(CadenceLane.MAINTENANCE, controller.decision().due_lanes)

    def test_requested_deep_context_runs_on_next_cycle_then_clears(self) -> None:
        now = [0.0]
        controller = CadenceController(
            fast_seconds=60.0,
            standard_seconds=300.0,
            deep_seconds=300.0,
            maintenance_seconds=300.0,
            monotonic=lambda: now[0],
        )
        controller.mark_completed(set(CadenceLane))
        now[0] = 60.0
        self.assertEqual(controller.decision().due_lanes, (CadenceLane.FAST,))
        controller.request(
            {CadenceLane.STANDARD, CadenceLane.DEEP, CadenceLane.MAINTENANCE}
        )
        requested = controller.decision()
        self.assertEqual(set(requested.due_lanes), set(CadenceLane))
        self.assertEqual(
            set(controller.state()["forced_due"]),
            {"standard", "deep", "maintenance"},
        )
        controller.mark_completed(requested.due_lanes)
        self.assertEqual(controller.state()["forced_due"], [])

    def test_scheduled_not_due_is_operationally_healthy_but_not_resolution_safe(self) -> None:
        base = (
            complete_domain("processes"),
            complete_domain("persistence"),
            domain("docker", enabled=False),
        )
        values = apply_collector_cadence(base, {"processes"})
        persistence = next(item for item in values if item.name == "persistence")
        self.assertEqual(persistence.state.value, "not_due")
        self.assertTrue(operationally_healthy(values))
        self.assertFalse(persistence.resolution_complete)
        self.assertEqual(cadence_counts(values)["scheduled_not_due"], 1)

    def test_required_degradation_is_not_operationally_healthy(self) -> None:
        values = (
            complete_domain("processes"),
            degraded_domain("persistence", reason_code="collector_error"),
        )
        self.assertFalse(operationally_healthy(values))
        self.assertEqual(cadence_counts(values)["degraded_required"], 1)


if __name__ == "__main__":
    unittest.main()
