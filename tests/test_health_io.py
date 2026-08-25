from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from quietward.health_io import HealthDurabilityPolicy, atomic_live_json


class HealthIoTests(unittest.TestCase):
    def test_only_unchanged_volatile_health_can_use_live_atomic_mode(self) -> None:
        policy = HealthDurabilityPolicy(checkpoint_seconds=300.0)
        key = ("healthy", "PASS", True, 0)
        self.assertTrue(policy.requires_durable(status="healthy", persistence_mode="volatile", material_key=key, now=0.0))
        policy.mark_durable(key, now=0.0)
        self.assertFalse(policy.requires_durable(status="healthy", persistence_mode="volatile", material_key=key, now=60.0))
        self.assertTrue(policy.requires_durable(status="healthy", persistence_mode="full", material_key=key, now=60.0))
        self.assertTrue(policy.requires_durable(status="healthy", persistence_mode=None, material_key=key, now=60.0))
        self.assertTrue(policy.requires_durable(status="degraded", persistence_mode="volatile", material_key=key, now=60.0))
        self.assertTrue(policy.requires_durable(status="healthy", persistence_mode="volatile", material_key=("healthy", "ATTENTION", True, 0), now=60.0))
        self.assertTrue(policy.requires_durable(status="healthy", persistence_mode="volatile", material_key=key, now=300.0))

    def test_live_atomic_writer_omits_fsync_but_keeps_atomic_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "health.json"
            with patch("quietward.health_io.os.fsync", side_effect=AssertionError("live health must not fsync"), create=True):
                atomic_live_json(path, {"status": "healthy", "health_write": {"mode": "live_atomic"}, "actions_executed": 0})
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["status"], "healthy")
            self.assertEqual(value["health_write"]["mode"], "live_atomic")
            self.assertEqual(value["actions_executed"], 0)
            self.assertEqual(list(path.parent.glob(".health.json.live-*")), [])

    def test_policy_state_is_bounded_and_action_free(self) -> None:
        policy = HealthDurabilityPolicy(checkpoint_seconds=120.0)
        policy.mark_durable(("key",), now=10.0)
        state = policy.state(now=40.0)
        self.assertEqual(state["checkpoint_seconds"], 120.0)
        self.assertEqual(state["seconds_since_durable"], 30.0)
        self.assertTrue(state["has_material_baseline"])
        self.assertEqual(state["actions_executed"], 0)


if __name__ == "__main__":
    unittest.main()
