from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from quietward.config import ScannerJobSettings
from quietward.scanners.execution import ScannerExecutor


class FakeProcess:
    def __init__(self, stdout: bytes, stderr: bytes = b"", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class ScannerExecutionTests(unittest.TestCase):
    target = Path(tempfile.gettempdir())

    def test_disabled_job_builds_no_commands(self) -> None:
        self.assertEqual(
            ScannerExecutor("host").build_commands(
                ScannerJobSettings("clamav", False, 60, 5, targets=(self.target,))
            ),
            [],
        )

    def test_clamav_command_is_bounded_and_no_update(self) -> None:
        argv, target = ScannerExecutor("host").build_commands(
            ScannerJobSettings("clamav", True, 60, 5, targets=(self.target,))
        )[0]
        self.assertEqual(target, str(self.target.resolve()))
        self.assertNotIn("freshclam", argv)
        self.assertIn("--cross-fs=no", argv)

    def test_yara_requires_rules(self) -> None:
        with self.assertRaisesRegex(ValueError, "rules_path"):
            ScannerExecutor("host").build_commands(
                ScannerJobSettings("yara", True, 60, 5, targets=(self.target,))
            )

    def test_trivy_forces_offline_and_skips_updates(self) -> None:
        argv, _ = ScannerExecutor("host").build_commands(
            ScannerJobSettings("trivy", True, 60, 5, targets=(self.target,))
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
            ScannerJobSettings("clamav", True, 60, 5, targets=(self.target,))
        )[0]
        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.to_dict()["actions_executed"], 0)

    def test_missing_scanner_is_nonfatal(self) -> None:
        result = ScannerExecutor(
            "host", executable_resolver=lambda _: None
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


if __name__ == "__main__":
    unittest.main()
