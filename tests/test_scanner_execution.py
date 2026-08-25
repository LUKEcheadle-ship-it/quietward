from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from quietward.config import ScannerJobSettings
from quietward.scanners.execution import ScannerExecutor
from quietward.windows_trust import WindowsTrustedPaths


class FakeProcess:
    def __init__(
        self,
        stdout: bytes,
        stderr: bytes = b"",
        returncode: int = 0,
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _test_windows_paths(root: Path) -> WindowsTrustedPaths:
    return WindowsTrustedPaths(
        windows=root,
        system=root,
        program_files=root,
        program_files_x86=None,
        local_app_data=root,
        app_data=root,
        program_data=root,
        user_profile=root,
        temp=root,
    )


class ScannerExecutionTests(unittest.TestCase):
    target = Path(tempfile.gettempdir()).resolve()

    def setUp(self) -> None:
        trusted = patch(
            "quietward.scanners.execution._regular_non_link_executable",
            return_value=True,
        )
        trusted.start()
        self.addCleanup(trusted.stop)
        if os.name == "nt":
            paths = patch(
                "quietward.scanners.execution.load_windows_trusted_paths",
                return_value=_test_windows_paths(self.target),
            )
            paths.start()
            self.addCleanup(paths.stop)

    def test_disabled_job_builds_no_commands(self) -> None:
        self.assertEqual(
            ScannerExecutor("host").build_commands(
                ScannerJobSettings(
                    "clamav",
                    False,
                    60,
                    5,
                    targets=(self.target,),
                )
            ),
            [],
        )

    def test_clamav_command_is_bounded_and_no_update(self) -> None:
        argv, target = ScannerExecutor("host").build_commands(
            ScannerJobSettings(
                "clamav",
                True,
                60,
                5,
                targets=(self.target,),
            )
        )[0]
        self.assertEqual(target, str(self.target.resolve()))
        self.assertNotIn("freshclam", argv)
        self.assertIn("--cross-fs=no", argv)

    def test_yara_requires_rules(self) -> None:
        with self.assertRaisesRegex(ValueError, "rules_path"):
            ScannerExecutor("host").build_commands(
                ScannerJobSettings(
                    "yara",
                    True,
                    60,
                    5,
                    targets=(self.target,),
                )
            )

    def test_trivy_forces_offline_and_skips_updates(self) -> None:
        argv, _ = ScannerExecutor("host").build_commands(
            ScannerJobSettings(
                "trivy",
                True,
                60,
                5,
                targets=(self.target,),
            )
        )[0]
        self.assertIn("--offline-scan", argv)
        self.assertIn("--skip-db-update", argv)
        self.assertIn("--skip-check-update", argv)

    def test_clamav_detection_is_normalized(self) -> None:
        def run(*args: object, **kwargs: object) -> FakeProcess:
            self.assertFalse(kwargs["shell"])
            return FakeProcess(
                b"/tmp/eicar: Win.Test.EICAR_HDB-1 FOUND\n",
                returncode=1,
            )

        result = ScannerExecutor(
            "host",
            executable_resolver=lambda _: str(self.target / "clamscan"),
            run_process=run,
        ).run(
            ScannerJobSettings(
                "clamav",
                True,
                60,
                5,
                targets=(self.target,),
            )
        )[0]
        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.to_dict()["actions_executed"], 0)

    def test_missing_scanner_is_nonfatal(self) -> None:
        result = ScannerExecutor(
            "host",
            executable_resolver=lambda _: None,
        ).run(
            ScannerJobSettings(
                "debsecan",
                True,
                60,
                5,
                data_source=self.target / "debsecan.json",
            )
        )[0]
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.returncode, 127)

    def test_debsecan_requires_local_data_source(self) -> None:
        with self.assertRaisesRegex(ValueError, "local data_source"):
            ScannerExecutor("host").build_commands(
                ScannerJobSettings("debsecan", True, 60, 5)
            )

    def test_timeout_is_reported(self) -> None:
        def run(*args: object, **kwargs: object):
            raise subprocess.TimeoutExpired(args[0], 1)

        result = ScannerExecutor(
            "host",
            executable_resolver=lambda _: str(self.target / "yara"),
            run_process=run,
        ).run(
            ScannerJobSettings(
                "yara",
                True,
                60,
                1,
                targets=(self.target,),
                rules_path=self.target / "rules.yar",
            )
        )[0]
        self.assertTrue(result.timed_out)
        self.assertEqual(result.status, "timeout")

    def test_invalid_trivy_json_returns_error_without_events(self) -> None:
        def run(*args: object, **kwargs: object) -> FakeProcess:
            return FakeProcess(b"{not-json", returncode=0)

        result = ScannerExecutor(
            "host",
            executable_resolver=lambda _: str(self.target / "trivy"),
            run_process=run,
        ).run(
            ScannerJobSettings(
                "trivy",
                True,
                60,
                5,
                targets=(self.target,),
            )
        )[0]
        self.assertEqual("error", result.status)
        self.assertEqual((), result.events)
        self.assertIn("invalid or incomplete", result.error or "")

    def test_truncated_scanner_output_is_not_parsed(self) -> None:
        def run(*args: object, **kwargs: object) -> FakeProcess:
            return FakeProcess(b"x" * 200, returncode=0)

        result = ScannerExecutor(
            "host",
            executable_resolver=lambda _: str(self.target / "trivy"),
            run_process=run,
        ).run(
            ScannerJobSettings(
                "trivy",
                True,
                60,
                5,
                targets=(self.target,),
                max_output_bytes=100,
            )
        )[0]
        self.assertEqual("error", result.status)
        self.assertTrue(result.output_truncated)
        self.assertEqual((), result.events)
        self.assertIn("safety limit", result.error or "")

    def test_relative_scanner_resolution_is_rejected(self) -> None:
        executor = ScannerExecutor(
            "host",
            executable_resolver=lambda _: "trivy",
            run_process=lambda *args, **kwargs: FakeProcess(b"{}"),
        )
        with self.assertRaisesRegex(ValueError, "absolute file"):
            executor.run(
                ScannerJobSettings(
                    "trivy",
                    True,
                    60,
                    5,
                    targets=(self.target,),
                )
            )


if __name__ == "__main__":
    unittest.main()
