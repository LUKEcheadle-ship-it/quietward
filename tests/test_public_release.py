from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.build_release_bundle import build
from scripts.public_release_audit import audit


class PublicReleaseTests(unittest.TestCase):
    def test_repository_audit_passes(self) -> None:
        root = Path(__file__).resolve().parents[1]
        report = audit(root)
        self.assertEqual(report["decision"], "PASS", report)
        self.assertEqual(report["actions_executed"], 0)
        self.assertFalse((root / "NOTICE").exists())

    def test_release_bundle_is_deterministic(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.zip"
            second = Path(temporary) / "second.zip"
            build(root, first)
            build(root, second)
            self.assertEqual(
                hashlib.sha256(first.read_bytes()).hexdigest(),
                hashlib.sha256(second.read_bytes()).hexdigest(),
            )

    def test_retired_brand_is_blocked_outside_compatibility_layer(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            for relative in (
                "LICENSE",
                "README.md",
                "SECURITY.md",
                "CONTRIBUTING.md",
                "CODE_OF_CONDUCT.md",
                "SUPPORT.md",
                "CHANGELOG.md",
                "docs/PRIVACY.md",
                "docs/FIRST_RUN.md",
                "docs/WINDOWS.md",
                "docs/RELEASE_CHECKLIST.md",
                "scripts/build_release_bundle.py",
                "scripts/build_release_candidate.ps1",
                "scripts/verify_release_bundle.py",
                "scripts/public_release_audit.py",
                "scripts/validate_release.sh",
                "scripts/install_windows.ps1",
                "scripts/uninstall_windows.ps1",
                "scripts/qualify_windows.ps1",
                ".github/ISSUE_TEMPLATE/bug_report.yml",
                ".github/ISSUE_TEMPLATE/feature_request.yml",
                ".github/ISSUE_TEMPLATE/config.yml",
                ".github/pull_request_template.md",
            ):
                path = fixture / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("placeholder", encoding="utf-8")
            (fixture / "pyproject.toml").write_text(
                '[project]\nname="quietward"\nversion="0.4.0a1"\n'
                '[project.scripts]\nquietward="quietward.console:main"\n',
                encoding="utf-8",
            )
            (fixture / "CHANGELOG.md").write_text(
                "## 0.4.0-alpha.1\n",
                encoding="utf-8",
            )
            notes = fixture / "docs/releases/v0.4.0-alpha.1.md"
            notes.parent.mkdir(parents=True, exist_ok=True)
            notes.write_text("release", encoding="utf-8")
            stale = fixture / "docs/stale.md"
            stale.write_text("Forge" + " Sentinel", encoding="utf-8")
            report = audit(fixture)
            self.assertEqual(report["decision"], "FAIL")
            self.assertTrue(
                any(
                    "retired QuietWard identifier" in item
                    for item in report["blockers"]
                )
            )


if __name__ == "__main__":
    unittest.main()
