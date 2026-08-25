from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from quietward import windows_trust

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release_paths.py"
spec = importlib.util.spec_from_file_location("release_paths_v05", SCRIPT)
assert spec is not None and spec.loader is not None
release_paths = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_paths)


def make_paths(root: Path) -> windows_trust.WindowsTrustedPaths:
    values = {
        "windows": root / "Windows",
        "system": root / "Windows" / "System32",
        "program_files": root / "Program Files",
        "program_files_x86": root / "Program Files (x86)",
        "local_app_data": root / "Users" / "test" / "AppData" / "Local",
        "app_data": root / "Users" / "test" / "AppData" / "Roaming",
        "program_data": root / "ProgramData",
        "user_profile": root / "Users" / "test",
        "temp": root / "Users" / "test" / "AppData" / "Local" / "Temp",
    }
    for value in values.values():
        value.mkdir(parents=True, exist_ok=True)
    return windows_trust.WindowsTrustedPaths(**values)


class ReleasePathsWindowsTrustTests(unittest.TestCase):
    def test_git_candidates_use_only_os_backed_program_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = make_paths(Path(directory).resolve())
            with mock.patch.dict(os.environ, {"ProgramFiles": str(paths.program_files.parent / "attacker"), "ProgramFiles(x86)": str(paths.program_files.parent / "attacker-x86")}, clear=False):
                candidates = release_paths._windows_git_candidates(paths)
            self.assertEqual(4, len(candidates))
            self.assertTrue(all("Git" in str(item) for item in candidates))
            self.assertTrue(all(str(item).startswith(str(paths.program_files)) or str(item).startswith(str(paths.program_files_x86)) for item in candidates))
            self.assertTrue(all("attacker" not in str(item) for item in candidates))

    def test_git_environment_ignores_poisoned_windows_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = make_paths(Path(directory).resolve())
            git = paths.program_files / "Git" / "cmd" / "git.exe"
            git.parent.mkdir(parents=True)
            git.write_bytes(b"test")
            git.chmod(0o755)
            with mock.patch.object(release_paths.os, "name", "nt"), mock.patch.object(release_paths, "load_windows_trusted_paths", return_value=paths), mock.patch.dict(os.environ, {"SystemRoot": "C:/attacker-windows", "ProgramFiles": "C:/attacker-program-files", "USERPROFILE": "C:/attacker-profile", "PATH": "C:/attacker-bin", "HOME": "C:/attacker-home"}, clear=False):
                environment = release_paths._git_environment(git)
            self.assertEqual(str(paths.windows), environment["SYSTEMROOT"])
            self.assertEqual(str(paths.user_profile), environment["HOME"])
            self.assertEqual(str(paths.system / "cmd.exe"), environment["COMSPEC"])
            self.assertNotIn("attacker", environment["PATH"].casefold())
            self.assertEqual("0", environment["GIT_TERMINAL_PROMPT"])
            self.assertEqual(os.devnull, environment["GIT_CONFIG_GLOBAL"])
            self.assertNotIn("PYTHONPATH", environment)
            self.assertNotIn("PYTHONHOME", environment)
            self.assertNotIn("PYTHONSTARTUP", environment)

    def test_resolver_fails_closed_without_os_backed_paths(self) -> None:
        with mock.patch.object(release_paths.os, "name", "nt"), mock.patch.object(release_paths, "load_windows_trusted_paths", return_value=None):
            self.assertIsNone(release_paths.resolve_trusted_git())

    def test_resolver_passes_only_approved_candidates_and_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = make_paths(Path(directory).resolve())
            expected = paths.program_files / "Git" / "cmd" / "git.exe"
            with mock.patch.object(release_paths.os, "name", "nt"), mock.patch.object(release_paths, "load_windows_trusted_paths", return_value=paths), mock.patch.object(release_paths, "trusted_executable", return_value=str(expected)) as resolver:
                observed = release_paths.resolve_trusted_git()
            self.assertEqual(str(expected).replace("\\", "/"), str(observed).replace("\\", "/"))
            candidates, roots = resolver.call_args.args
            self.assertEqual(release_paths._windows_git_candidates(paths), candidates)
            self.assertEqual(paths.executable_roots, roots)


if __name__ == "__main__":
    unittest.main()
