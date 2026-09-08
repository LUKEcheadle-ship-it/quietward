from __future__ import annotations

import importlib.util
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "quick_demo.py"
SPEC = importlib.util.spec_from_file_location("quietward_quick_demo", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)


class QuickDemoTests(unittest.TestCase):
    def test_demo_is_synthetic_useful_and_observation_only(self) -> None:
        result = DEMO.build_demo_result(datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc))
        self.assertEqual(result["demo"], "quietward-safe-synthetic-demo-v1")
        self.assertEqual(result["analysis"]["events_analyzed"], 3)
        self.assertGreaterEqual(len(result["analysis"]["findings"]), 3)
        self.assertEqual(result["analysis"]["actions_executed"], 0)
        self.assertFalse(any(item["executable_in_current_mode"] for item in result["analysis"]["action_proposals"]))
        self.assertEqual(
            result["safety"],
            {
                "synthetic_data_only": True,
                "host_observation_performed": False,
                "host_state_changed": False,
                "network_request_performed": False,
                "actions_executed": 0,
            },
        )

    def test_demo_requires_timezone_aware_timestamp(self) -> None:
        with self.assertRaises(ValueError):
            DEMO.build_demo_events(datetime(2026, 9, 7, 12, 0))


if __name__ == "__main__":
    unittest.main()
