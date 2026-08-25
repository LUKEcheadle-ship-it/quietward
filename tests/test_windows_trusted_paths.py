from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from quietward import windows_trust
from quietward.collectors import command as command_module
from quietward.scanners import execution as scanner_module


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


class WindowsTrustedPathTests(unittest.TestCase):
    def test_os_backed_providers_ignore_poisoned_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            expected = make_paths(root)
            known = {
                windows_trust.CSIDL_PROGRAM_FILES: expected.program_files,
                windows_trust.CSIDL_PROGRAM_FILES_X86: expected.program_files_x86,
                windows_trust.CSIDL_LOCAL_APPDATA: expected.local_app_data,
                windows_trust.CSIDL_APPDATA: expected.app_data,
                windows_trust.CSIDL_COMMON_APPDATA: expected.program_data,
                windows_trust.CSIDL_PROFILE: expected.user_profile,
            }
            with mock.patch.dict(
                os.environ,
                {
                    "SystemRoot": str(root / "attacker-windows"),
                    "ProgramFiles": str(root / "attacker-program-files"),
                    "ProgramFiles(x86)": str(root / "attacker-program-files-x86"),
                    "LOCALAPPDATA": str(root / "attacker-local-app-data"),
                    "PATH": str(root / "attacker-bin"),
                },
                clear=False,
            ):
                observed = windows_trust.load_windows_trusted_paths(
                    windows_provider=lambda: expected.windows,
                    system_provider=lambda: expected.system,
                    temp_provider=lambda: expected.temp,
                    known_folder_provider=known.get,
                )
            self.assertEqual(expected, observed)

    def test_missing_required_os_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            expected = make_paths(root)
            known = {
                windows_trust.CSIDL_PROGRAM_FILES: expected.program_files,
                windows_trust.CSIDL_PROGRAM_FILES_X86: expected.program_files_x86,
                windows_trust.CSIDL_LOCAL_APPDATA: None,
                windows_trust.CSIDL_APPDATA: expected.app_data,
                windows_trust.CSIDL_COMMON_APPDATA: expected.program_data,
                windows_trust.CSIDL_PROFILE: expected.user_profile,
            }
            observed = windows_trust.load_windows_trusted_paths(
                windows_provider=lambda: expected.windows,
                system_provider=lambda: expected.system,
                temp_provider=lambda: expected.temp,
                known_folder_provider=known.get,
            )
            self.assertIsNone(observed)

    def test_linked_trusted_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            expected = make_paths(root)
            link = root / "linked-program-files"
            try:
                link.symlink_to(expected.program_files, target_is_directory=True)
            except OSError:
                self.skipTest("directory symlinks are unavailable")
            known = {
                windows_trust.CSIDL_PROGRAM_FILES: link,
                windows_trust.CSIDL_PROGRAM_FILES_X86: expected.program_files_x86,
                windows_trust.CSIDL_LOCAL_APPDATA: expected.local_app_data,
                windows_trust.CSIDL_APPDATA: expected.app_data,
                windows_trust.CSIDL_COMMON_APPDATA: expected.program_data,
                windows_trust.CSIDL_PROFILE: expected.user_profile,
            }
            observed = windows_trust.load_windows_trusted_paths(
                windows_provider=lambda: expected.windows,
                system_provider=lambda: expected.system,
                temp_provider=lambda: expected.temp,
                known_folder_provider=known.get,
            )
            self.assertIsNone(observed)

    def test_executable_inside_approved_root_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            executable = root / "tool.exe"
            executable.write_bytes(b"test")
            executable.chmod(0o755)
            self.assertEqual(
                str(executable),
                windows_trust.trusted_executable((executable,), (root,)),
            )

    def test_executable_outside_approved_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "trusted"
            root.mkdir()
            executable = base / "attacker.exe"
            executable.write_bytes(b"test")
            executable.chmod(0o755)
            self.assertIsNone(
                windows_trust.trusted_executable((executable,), (root,))
            )

    def test_linked_executable_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            actual = root / "actual.exe"
            actual.write_bytes(b"test")
            actual.chmod(0o755)
            link = root / "linked.exe"
            try:
                link.symlink_to(actual)
            except OSError:
                self.skipTest("file symlinks are unavailable")
            self.assertIsNone(
                windows_trust.trusted_executable((link,), (root,))
            )

    def test_environment_uses_only_resolved_os_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = make_paths(Path(directory).resolve())
            executable = paths.system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"test")
            executable.chmod(0o755)
            with mock.patch.dict(
                os.environ,
                {
                    "SystemRoot": "C:/attacker",
                    "ProgramFiles": "C:/attacker-programs",
                    "LOCALAPPDATA": "C:/attacker-local",
                    "PATH": "C:/attacker-bin",
                },
                clear=False,
            ):
                env = windows_trust.trusted_windows_environment(
                    executable,
                    paths,
                    deny_network_updates=True,
                )
            self.assertEqual(str(paths.windows), env["SYSTEMROOT"])
            self.assertEqual(str(paths.local_app_data), env["LOCALAPPDATA"])
            self.assertNotIn("attacker", env["PATH"].casefold())
            self.assertEqual("*", env["NO_PROXY"])
            self.assertNotIn("PYTHONPATH", env)
            self.assertNotIn("PYTHONHOME", env)
            self.assertNotIn("PYTHONSTARTUP", env)

    def test_collector_candidates_use_resolved_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = make_paths(Path(directory).resolve())
            candidates = command_module._windows_candidates("powershell.exe", paths)
            self.assertEqual(
                (
                    paths.system
                    / "WindowsPowerShell"
                    / "v1.0"
                    / "powershell.exe",
                ),
                candidates,
            )
            docker = command_module._windows_candidates("docker", paths)
            self.assertTrue(all("Docker" in str(item) for item in docker))
            self.assertTrue(all("attacker" not in str(item) for item in docker))

    def test_scanner_candidates_use_resolved_program_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = make_paths(Path(directory).resolve())
            candidates = scanner_module._windows_scanner_candidates("yara", paths)
            self.assertEqual(4, len(candidates))
            self.assertTrue(all("YARA" in str(item) for item in candidates))
            self.assertTrue(
                all(
                    str(item).startswith(str(paths.program_files))
                    or str(item).startswith(str(paths.program_files_x86))
                    for item in candidates
                )
            )

    @unittest.skipUnless(os.name == "nt", "requires native Windows APIs")
    def test_production_resolver_ignores_poisoned_windows_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            malicious = root / "Windows" / "System32" / "WindowsPowerShell" / "v1.0"
            malicious.mkdir(parents=True)
            fake = malicious / "powershell.exe"
            fake.write_bytes(b"fake")
            with mock.patch.dict(
                os.environ,
                {
                    "SystemRoot": str(root / "Windows"),
                    "ProgramFiles": str(root / "Program Files"),
                    "ProgramFiles(x86)": str(root / "Program Files (x86)"),
                    "LOCALAPPDATA": str(root / "LocalAppData"),
                    "PATH": str(malicious),
                },
                clear=False,
            ):
                resolved = command_module.resolve_trusted_executable("powershell.exe")
            self.assertIsNotNone(resolved)
            self.assertNotEqual(fake.resolve(), Path(resolved).resolve())


if __name__ == "__main__":
    unittest.main()
