from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path

from quietward import __version__

ROOT = Path(__file__).resolve().parents[1]
VERIFY_PATH = ROOT / "scripts" / "verify_release_bundle.py"
SPEC = importlib.util.spec_from_file_location("verify_release_bundle", VERIFY_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class ReleaseCandidateToolingTests(unittest.TestCase):
    def test_version_metadata_is_consistent(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        package_version = str(project["project"]["version"])
        version = VERIFY.display_version(package_version)
        self.assertEqual("quietward", project["project"]["name"])
        self.assertEqual(package_version, __version__)
        self.assertIn(f"## {version}", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))
        self.assertTrue((ROOT / "docs" / "releases" / f"v{version}.md").is_file())

    def test_release_notes_have_no_placeholders(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        version = VERIFY.display_version(str(project["project"]["version"]))
        notes = (ROOT / "docs" / "releases" / f"v{version}.md").read_text(encoding="utf-8")
        lower = notes.lower()
        self.assertNotIn("PENDING", notes)
        self.assertIn("checksum sidecar", lower)
        self.assertIn("exact public release sha", lower)
        self.assertIn("windows 11", lower)
        self.assertIn("debian 12", lower)
        self.assertIn(f"quietward-v{version}-source.zip", notes)

    def test_windows_release_wrappers_delegate_without_extra_authority(self) -> None:
        expected = {
            "install_windows.ps1": "install_windows_preview.ps1",
            "uninstall_windows.ps1": "uninstall_windows_preview.ps1",
            "qualify_windows.ps1": "qualify_windows_preview.ps1",
        }
        forbidden = ("Invoke-Expression", "iex ", "Invoke-WebRequest", "Start-BitsTransfer", "winget ")
        for wrapper, target in expected.items():
            text = (ROOT / "scripts" / wrapper).read_text(encoding="utf-8")
            self.assertIn(target, text)
            for marker in forbidden:
                self.assertNotIn(marker, text)

    def test_linux_migration_installer_restores_legacy_service_on_any_failed_attempt(self) -> None:
        text = (ROOT / "scripts" / "install_user_service.sh").read_text(encoding="utf-8")
        self.assertIn("legacy_service_stop_attempted=false", text)
        self.assertIn("legacy_service_stop_attempted=true", text)
        self.assertIn("trap 'rollback_migration $?' ERR", text)
        self.assertIn(
            "if ${legacy_service_stop_attempted} && ! ${migration_finalized}; then",
            text,
        )
        legacy_service = "forge" + "-sentinel.service"
        self.assertIn(f"systemctl --user start {legacy_service}", text)
        self.assertGreaterEqual(text.count("rollback_migration 2"), 3)

    def test_release_builder_is_offline_and_non_publishing(self) -> None:
        text = (ROOT / "scripts" / "build_release_candidate.ps1").read_text(encoding="utf-8")
        for marker in (
            "Invoke-WebRequest",
            "Start-BitsTransfer",
            "winget ",
            "git push",
            "gh release",
            "Set-ExecutionPolicy",
        ):
            self.assertNotIn(marker, text)
        self.assertIn("deterministic", text.lower())
        self.assertIn("actions_executed", text)
        self.assertIn('quietward-v${DisplayVersion}-source.zip', text)
        self.assertIn("SkipTests is forbidden", text)
        self.assertIn("validate_migrated_release.py", text)

    def test_release_builder_uses_safe_powershell_interpolation(self) -> None:
        text = (ROOT / "scripts" / "build_release_candidate.ps1").read_text(encoding="utf-8")
        self.assertNotIn("exit code $LASTEXITCODE:", text)
        self.assertIn("exit code ${LASTEXITCODE}:", text)

    def test_release_builder_resolves_default_output_after_parameter_binding(self) -> None:
        text = (ROOT / "scripts" / "build_release_candidate.ps1").read_text(encoding="utf-8")
        parameter_block = text.split(")\n\n$ErrorActionPreference", 1)[0]
        self.assertNotIn("$PSScriptRoot", parameter_block)
        self.assertIn("IsNullOrWhiteSpace($OutputDirectory)", text)
        self.assertIn('$OutputDirectory = Join-Path $Root "dist"', text)

    def test_release_builder_imports_src_without_installing_the_project(self) -> None:
        text = (ROOT / "scripts" / "build_release_candidate.ps1").read_text(encoding="utf-8")
        self.assertIn('$SourcePath = Join-Path $Root "src"', text)
        self.assertIn('$env:PYTHONPATH = $SourcePath', text)
        self.assertIn('$env:PYTHONPATH = $PreviousPythonPath', text)

    def _archive(self, path: Path, *, tamper: bool = False, manifest_root: object | None = None) -> None:
        files: dict[str, bytes] = {name: b"placeholder\n" for name in VERIFY.REQUIRED}
        files["pyproject.toml"] = b'[project]\nname="quietward"\nversion="0.4.0a1"\n'
        files["CHANGELOG.md"] = b"# Changelog\n\n## 0.4.0-alpha.1\n"
        files["docs/releases/v0.4.0-alpha.1.md"] = b"# Release\n"
        entries = [
            {"path": name, "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
            for name, payload in sorted(files.items())
        ]
        manifest = manifest_root if manifest_root is not None else {
            "format": VERIFY.MANIFEST_FORMAT,
            "project": "quietward",
            "version": "0.4.0a1",
            "files": entries,
        }
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload in sorted(files.items()):
                archive.writestr(name, payload + (b"tampered" if tamper and name == "README.md" else b""))
            archive.writestr(VERIFY.MANIFEST, json.dumps(manifest, sort_keys=True))

    def test_archive_verifier_accepts_valid_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "candidate.zip"
            self._archive(archive)
            result = VERIFY.verify(archive)
            self.assertEqual("PASS", result["decision"], result)
            self.assertEqual("0.4.0-alpha.1", result["version"])
            self.assertEqual("0.4.0a1", result["manifest_version"])
            self.assertEqual(0, result["actions_executed"])

    def test_archive_verifier_rejects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "candidate.zip"
            self._archive(archive, tamper=True)
            result = VERIFY.verify(archive)
            self.assertEqual("FAIL", result["decision"])
            self.assertTrue(any("README.md" in item for item in result["blockers"]))

    def test_archive_verifier_rejects_non_object_manifest_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "candidate.zip"
            self._archive(archive, manifest_root=[])
            result = VERIFY.verify(archive)
            self.assertEqual("FAIL", result["decision"])
            self.assertTrue(any("manifest root" in item for item in result["blockers"]))


if __name__ == "__main__":
    unittest.main()
