from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.validate_v05_candidate import _diagnostics_directory, _failure_excerpt, _run


class CandidateDiagnosticsTests(unittest.TestCase):
    def test_failure_excerpt_promotes_nested_failing_unittest_output(self) -> None:
        value = {"decision": "FAIL", "results": [{"command": ["python", "-m", "unittest", "-v", "tests.example"], "returncode": 1, "stdout": "", "stderr": "ERROR: test_exact_failure\nRuntimeError: exact diagnostic\n"}]}
        excerpt = _failure_excerpt(value); self.assertIn("test_exact_failure", excerpt); self.assertIn("exact diagnostic", excerpt)

    def test_diagnostics_directory_is_outside_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve(); checkout = base / "checkout"; checkout.mkdir(); external = base / "diagnostics"; result = _diagnostics_directory(checkout, external); self.assertTrue(result.is_dir())
            with self.assertRaisesRegex(ValueError, "outside the checkout"): _diagnostics_directory(checkout, checkout / "logs")

    def test_run_preserves_full_stage_logs_and_compact_failure_excerpt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); diagnostics = root / "diagnostics"; diagnostics.mkdir(); payload = {"decision": "FAIL", "results": [{"command": ["python", "-m", "unittest"], "returncode": 1, "stdout": "", "stderr": "FAIL: test_visible\nAssertionError: visible detail\n"}]}
            completed = subprocess.CompletedProcess(args=["python", "child.py"], returncode=1, stdout=json.dumps(payload), stderr="parent stderr detail\n")
            with mock.patch("scripts.validate_v05_candidate.subprocess.run", return_value=completed):
                result = _run(("python", "child.py"), root=root, environment={}, diagnostics_dir=diagnostics, stage="core_development")
            self.assertEqual(1, result["returncode"]); self.assertIn("test_visible", result["failure_excerpt"]); self.assertEqual(json.dumps(payload), (diagnostics / "core_development.stdout.log").read_text(encoding="utf-8")); self.assertEqual("parent stderr detail\n", (diagnostics / "core_development.stderr.log").read_text(encoding="utf-8"))


if __name__ == "__main__": unittest.main()
