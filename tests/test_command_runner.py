from __future__ import annotations

import unittest

from quietward.collectors.command import PS_COMMAND, ReadOnlyCommandRunner


class CommandRunnerTests(unittest.TestCase):
    def test_exact_read_only_command_allowed(self) -> None:
        self.assertEqual(ReadOnlyCommandRunner.validate(PS_COMMAND), PS_COMMAND)

    def test_shell_command_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "shell"):
            ReadOnlyCommandRunner.validate(("bash", "-lc", "id"))

    def test_mutating_docker_command_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "allowlist"):
            ReadOnlyCommandRunner.validate(("docker", "stop", "container"))


if __name__ == "__main__":
    unittest.main()
