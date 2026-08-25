from __future__ import annotations

import unittest

from quietward.collectors.command import ReadOnlyCommandRunner
from quietward.collectors.windows import WindowsReadOnlyCollector
from quietward.collectors.windows_commands import POWERSHELL_PREFIX
from quietward.collectors.windows_fast_core_command import (
    FAST_CORE_SCRIPT,
    WINDOWS_FAST_CORE_COMMAND,
)


class WindowsFastCoreSafetyTests(unittest.TestCase):
    def test_fast_script_contains_only_fresh_process_and_listener_inventory(self) -> None:
        lowered = FAST_CORE_SCRIPT.casefold()
        for required in (
            "get-ciminstance win32_process",
            "get-nettcpconnection -state listen",
            "convertto-json",
        ):
            self.assertIn(required, lowered)

        for forbidden in (
            "get-mpcomputerstatus",
            "get-mpthreat",
            "get-mpthreatdetection",
            "get-process -includeusername",
            "get-scheduledtask",
            "win32_service",
            "currentversion\\run",
            "currentversion\\runonce",
            "get-itemproperty",
            "new-item",
            "set-item",
            "remove-item",
            "start-process",
            "stop-process",
            "invoke-webrequest",
            "invoke-restmethod",
        ):
            self.assertNotIn(
                forbidden,
                lowered,
                f"FAST inventory must not contain slow/mutation primitive {forbidden}",
            )

    def test_fast_command_is_one_fixed_powershell_invocation(self) -> None:
        self.assertEqual(
            WINDOWS_FAST_CORE_COMMAND[:-1],
            POWERSHELL_PREFIX,
        )
        self.assertEqual(WINDOWS_FAST_CORE_COMMAND[-1], FAST_CORE_SCRIPT)
        self.assertEqual(
            ReadOnlyCommandRunner.validate(
                WINDOWS_FAST_CORE_COMMAND,
                additional_commands=(WINDOWS_FAST_CORE_COMMAND,),
            ),
            WINDOWS_FAST_CORE_COMMAND,
        )

    def test_production_windows_runner_registers_exact_fast_command(self) -> None:
        collector = WindowsReadOnlyCollector(host_id="host-test")
        self.assertIn(
            WINDOWS_FAST_CORE_COMMAND,
            collector.runner.additional_commands,
        )
        self.assertEqual(collector.runner.performance_snapshot()["actions_executed"], 0)


if __name__ == "__main__":
    unittest.main()
