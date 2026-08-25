from __future__ import annotations

import unittest

from quietward.collectors.command import PS_COMMAND, CommandResult, ReadOnlyCommandRunner


class CommandPerformanceMetricsTests(unittest.TestCase):
    def test_legacy_command_result_construction_keeps_zero_duration_default(self) -> None:
        result = CommandResult(("ps",), 0, "out", "err", False)
        self.assertEqual(result.duration_ms, 0.0)

    def test_unavailable_command_is_counted_without_exposing_argv_in_metrics(self) -> None:
        runner = ReadOnlyCommandRunner(executable_resolver=lambda _binary: None)
        result = runner.run(PS_COMMAND)
        self.assertEqual(result.returncode, 127)
        self.assertGreaterEqual(result.duration_ms, 0.0)
        metrics = runner.performance_snapshot()
        self.assertEqual(metrics["commands_executed"], 1)
        self.assertGreaterEqual(metrics["command_duration_ms"], 0.0)
        self.assertNotIn("argv", metrics)
        self.assertNotIn("command", metrics)
        self.assertFalse(metrics["shell_used"])
        self.assertEqual(metrics["actions_executed"], 0)


if __name__ == "__main__":
    unittest.main()
