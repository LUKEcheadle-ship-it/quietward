from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from quietward.config import QuietWardConfig
from quietward.models import HybridRiskScorer
from quietward.runtime import build_pipeline, bundled_model_path


class RuntimeTests(unittest.TestCase):
    def test_bundled_model_is_loadable(self) -> None:
        path = bundled_model_path()
        self.assertTrue(path.exists())
        self.assertEqual(path.name, "quietward_priority_tiny_v1.json")
        self.assertLess(path.stat().st_size, 10000)

    def test_tiny_model_is_opt_in(self) -> None:
        state = str(Path(tempfile.gettempdir()) / "quietward-runtime")
        config = QuietWardConfig.from_dict({"state_dir": state})
        self.assertNotIsInstance(build_pipeline(config).scorer, HybridRiskScorer)
        enabled = QuietWardConfig.from_dict(
            {"state_dir": state, "tiny_model": {"enabled": True}}
        )
        self.assertIsInstance(build_pipeline(enabled).scorer, HybridRiskScorer)


if __name__ == "__main__":
    unittest.main()
