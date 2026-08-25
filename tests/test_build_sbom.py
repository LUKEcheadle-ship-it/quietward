from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_sbom.py"
spec = importlib.util.spec_from_file_location("build_sbom", SCRIPT)
assert spec is not None and spec.loader is not None
build_sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_sbom)

COMMIT = "1" * 40
CREATED = "2026-08-06T16:00:00Z"


class BuildSbomTests(unittest.TestCase):
    def make_root(self, directory: str) -> Path:
        root = Path(directory) / "root"
        root.mkdir()
        (root / "pyproject.toml").write_text(
            """[project]\nname = "quietward"\nversion = "0.5.0a1"\nlicense = {text = "MIT"}\n""",
            encoding="utf-8",
        )
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text("print('safe')\n", encoding="utf-8")
        return root

    def test_document_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            files = build_sbom.discover_files(root)
            first = build_sbom.generate_sbom(
                root, files, created=CREATED, source_commit=COMMIT
            )
            second = build_sbom.generate_sbom(
                root, files, created=CREATED, source_commit=COMMIT
            )
            self.assertEqual(first, second)
            self.assertEqual("SPDX-2.3", first["spdxVersion"])
            self.assertEqual(2, len(first["files"]))
            self.assertEqual(0, json.loads(json.dumps({"actions_executed": 0}))["actions_executed"])

    def test_file_change_changes_verification_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            files = build_sbom.discover_files(root)
            first = build_sbom.generate_sbom(
                root, files, created=CREATED, source_commit=COMMIT
            )
            (root / "src" / "app.py").write_text("print('changed')\n", encoding="utf-8")
            second = build_sbom.generate_sbom(
                root, files, created=CREATED, source_commit=COMMIT
            )
            self.assertNotEqual(
                first["packages"][0]["packageVerificationCode"],
                second["packages"][0]["packageVerificationCode"],
            )

    def test_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            link = root / "linked.py"
            try:
                link.symlink_to(root / "src" / "app.py")
            except OSError:
                self.skipTest("symlinks unavailable")
            with self.assertRaises(ValueError):
                build_sbom.discover_files(root)

    def test_directory_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            outside = Path(directory) / "outside"
            outside.mkdir()
            (outside / "private.txt").write_text("private", encoding="utf-8")
            link = root / "linked-directory"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("directory symlinks unavailable")
            with self.assertRaises(ValueError):
                build_sbom.discover_files(root)

    def test_existing_output_is_not_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "sbom.json"
            output.write_text("preserve", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                build_sbom.write_sbom(output, {})
            self.assertEqual("preserve", output.read_text(encoding="utf-8"))

    def test_invalid_commit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            with self.assertRaises(ValueError):
                build_sbom.generate_sbom(
                    root,
                    build_sbom.discover_files(root),
                    created=CREATED,
                    source_commit="short",
                )


if __name__ == "__main__":
    unittest.main()
