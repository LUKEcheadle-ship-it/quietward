from __future__ import annotations

import json
import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from quietward.cadence import CadenceController, CadenceLane
from quietward.warm_start import evaluate_warm_start


NOW = datetime(2026, 8, 8, 15, 0, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class FakeSnapshot:
    observed_at: datetime
    errors: tuple[str, ...] = ()


class FakeStore:
    def __init__(
        self,
        *,
        snapshot: FakeSnapshot | None,
        coverage: dict[str, object] | None,
        evidence_valid: bool = True,
        active_lanes=frozenset(),
    ) -> None:
        self.snapshot = snapshot
        self.coverage = coverage
        self.evidence_valid = evidence_valid
        self.active_lanes = frozenset(active_lanes)
        self.verify_calls = 0

    def latest_snapshot(self):
        return self.snapshot

    def get_metadata(self, key: str):
        if key != "last_coverage_report" or self.coverage is None:
            return None
        return json.dumps(self.coverage)

    def verify_evidence_chain(self):
        self.verify_calls += 1
        return {"valid": self.evidence_valid, "actions_executed": 0}

    def active_incident_lanes(self):
        return self.active_lanes


def established_coverage(*, observed_at: datetime = NOW) -> dict[str, object]:
    return {
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "operationally_healthy": True,
        "resolution_safe": True,
        "baseline": {
            "ready": True,
            "established": True,
            "confidence": "established",
        },
    }


class WarmStartTests(unittest.TestCase):
    def test_recent_established_verified_state_stages_heavy_lanes(self) -> None:
        store = FakeStore(
            snapshot=FakeSnapshot(NOW - timedelta(seconds=60)),
            coverage=established_coverage(observed_at=NOW - timedelta(seconds=30)),
        )
        plan = evaluate_warm_start(store, fast_seconds=60.0, now=NOW)
        self.assertTrue(plan.eligible)
        self.assertTrue(plan.evidence_valid)
        self.assertEqual(plan.due_in_seconds[CadenceLane.FAST], 0.0)
        self.assertEqual(plan.due_in_seconds[CadenceLane.STANDARD], 60.0)
        self.assertEqual(plan.due_in_seconds[CadenceLane.DEEP], 120.0)
        self.assertEqual(plan.due_in_seconds[CadenceLane.MAINTENANCE], 180.0)
        self.assertEqual(store.verify_calls, 1)
        self.assertEqual(plan.to_dict()["actions_executed"], 0)

    def test_active_heavy_incident_lane_remains_immediately_due(self) -> None:
        store = FakeStore(
            snapshot=FakeSnapshot(NOW - timedelta(seconds=60)),
            coverage=established_coverage(),
            active_lanes={CadenceLane.MAINTENANCE},
        )
        plan = evaluate_warm_start(store, fast_seconds=60.0, now=NOW)
        self.assertTrue(plan.eligible)
        self.assertEqual(plan.due_in_seconds[CadenceLane.MAINTENANCE], 0.0)
        self.assertEqual(plan.protected_lanes, (CadenceLane.MAINTENANCE,))

    def test_stale_snapshot_falls_back_before_evidence_verification(self) -> None:
        store = FakeStore(
            snapshot=FakeSnapshot(NOW - timedelta(minutes=10)),
            coverage=established_coverage(),
        )
        plan = evaluate_warm_start(store, fast_seconds=60.0, now=NOW)
        self.assertFalse(plan.eligible)
        self.assertEqual(plan.reason, "snapshot_stale")
        self.assertEqual(store.verify_calls, 0)

    def test_unestablished_baseline_falls_back_cold(self) -> None:
        coverage = established_coverage()
        coverage["baseline"] = {
            "ready": True,
            "established": False,
            "confidence": "initial",
        }
        store = FakeStore(
            snapshot=FakeSnapshot(NOW - timedelta(seconds=30)),
            coverage=coverage,
        )
        plan = evaluate_warm_start(store, fast_seconds=60.0, now=NOW)
        self.assertFalse(plan.eligible)
        self.assertEqual(plan.reason, "baseline_not_established")
        self.assertEqual(store.verify_calls, 0)

    def test_invalid_evidence_falls_back_cold(self) -> None:
        store = FakeStore(
            snapshot=FakeSnapshot(NOW - timedelta(seconds=30)),
            coverage=established_coverage(),
            evidence_valid=False,
        )
        plan = evaluate_warm_start(store, fast_seconds=60.0, now=NOW)
        self.assertFalse(plan.eligible)
        self.assertEqual(plan.reason, "evidence_invalid")
        self.assertEqual(store.verify_calls, 1)

    def test_restored_schedule_runs_fast_first_then_revalidation(self) -> None:
        monotonic = [100.0]
        controller = CadenceController(
            fast_seconds=60.0,
            standard_seconds=300.0,
            deep_seconds=300.0,
            maintenance_seconds=300.0,
            monotonic=lambda: monotonic[0],
        )
        controller.restore_due_schedule(
            {
                CadenceLane.FAST: 0.0,
                CadenceLane.STANDARD: 60.0,
                CadenceLane.DEEP: 120.0,
                CadenceLane.MAINTENANCE: 180.0,
            }
        )
        first = controller.decision()
        self.assertFalse(first.first_cycle)
        self.assertEqual(first.due_lanes, (CadenceLane.FAST,))
        controller.mark_completed(first.due_lanes)

        monotonic[0] = 160.0
        second = controller.decision()
        self.assertIn(CadenceLane.FAST, second.due_lanes)
        self.assertIn(CadenceLane.STANDARD, second.due_lanes)
        self.assertNotIn(CadenceLane.DEEP, second.due_lanes)
        self.assertTrue(controller.state()["restored_schedule"])


if __name__ == "__main__":
    unittest.main()
