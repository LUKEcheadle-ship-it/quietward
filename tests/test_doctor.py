from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from quietward.config import QuietWardConfig
from quietward.doctor import run_doctor


class DoctorTests(unittest.TestCase):
    def test_safe_minimal_doctor_has_zero_actions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch("shutil.which", return_value="/usr/bin/tool"):
            key = Path(temporary) / "privacy.key"
            key.write_bytes(b"k" * 32)
            key.chmod(0o600)
            report = run_doctor(
                QuietWardConfig.from_dict(
                    {
                        "state_dir": temporary,
                        "collector": {
                            "include_auth_journal": False,
                            "privacy_identity_key_path": str(key),
                        },
                    }
                )
            )
            self.assertEqual(report["decision"], "PASS")
            self.assertEqual(report["safety"]["actions_executed"], 0)
            self.assertFalse(report["safety"]["network_updates_performed"])


if __name__ == "__main__":
    unittest.main()
