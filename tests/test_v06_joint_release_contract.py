from __future__ import annotations

import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from quietward import __version__


class JointReleaseContractTests(unittest.TestCase):
    def test_preview_version_and_packaging_metadata_are_consistent(self) -> None:
        self.assertEqual(__version__, "0.6.0a1")
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = pyproject.get("project") or {}
        static_version = project.get("version")
        if static_version is not None:
            self.assertEqual(static_version, __version__)

    def test_handoff_source_contains_no_response_client_or_unkeyed_finding_field(self) -> None:
        paths = [
            ROOT / "src" / "quietward" / "integrations" / "response.py",
            ROOT / "scripts" / "export_response_handoff.py",
            ROOT / "scripts" / "run_response_handoff_outbox.py",
        ]
        text = "\n".join(path.read_text(encoding="utf-8").lower() for path in paths)
        for forbidden in (
            "quietward_finding_id",
            "urllib.request",
            "requests.",
            "httpx.",
            "urlopen(",
            "import subprocess",
            "from subprocess",
            "os.system(",
            "shell=true",
        ):
            self.assertNotIn(forbidden, text)

    def test_handoff_source_has_no_destructive_executor_names(self) -> None:
        paths = [
            ROOT / "src" / "quietward" / "integrations" / "response.py",
            ROOT / "scripts" / "run_response_handoff_outbox.py",
        ]
        text = "\n".join(path.read_text(encoding="utf-8").lower() for path in paths)
        for forbidden in (
            "terminate_process_by_handle",
            "quarantine_artifact_by_handle",
            "restore_quarantined_artifact_by_handle",
            "block_network",
            "isolate_host",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
