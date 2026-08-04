from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from quietward.config import QuietWardConfig


class ConfigTests(unittest.TestCase):
    def test_safe_defaults_parse(self) -> None:
        config = QuietWardConfig.from_dict(
            {"state_dir": str(Path(tempfile.gettempdir()) / "quietward-test")}
        )
        self.assertEqual(config.mode, "observe_only")
        self.assertFalse(config.micro_llm.enabled)
        self.assertEqual(config.dashboard.bind, "127.0.0.1")
        self.assertTrue(config.storage.database_path.is_absolute())
        self.assertEqual(config.storage.database_path.name, "quietward.sqlite3")

    def test_action_execution_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "execute"):
            QuietWardConfig.from_dict(
                {"state_dir": "/tmp/quietward-test", "actions": {"execute": True}}
            )

    def test_public_listener_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "public_listener"):
            QuietWardConfig.from_dict(
                {
                    "state_dir": "/tmp/quietward-test",
                    "network": {"public_listener": True},
                }
            )

    def test_scanner_targets_must_be_absolute(self) -> None:
        with self.assertRaisesRegex(ValueError, "absolute"):
            QuietWardConfig.from_dict(
                {
                    "state_dir": "/tmp/quietward-test",
                    "scanners": [
                        {"scanner": "clamav", "enabled": True, "targets": ["relative"]}
                    ],
                }
            )

    def test_unknown_fields_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown"):
            QuietWardConfig.from_dict(
                {"state_dir": "/tmp/quietward-test", "surprise": True}
            )


if __name__ == "__main__":
    unittest.main()
