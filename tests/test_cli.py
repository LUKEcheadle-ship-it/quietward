from __future__ import annotations

import unittest

from quietward.cli import build_parser


class CLITests(unittest.TestCase):
    def test_production_commands_exist(self) -> None:
        parser = build_parser()
        self.assertEqual(parser.prog, "quietward")
        for command in ("run", "serve", "status", "doctor", "scan", "model-info"):
            args = parser.parse_args([command])
            self.assertEqual(args.command, command)


if __name__ == "__main__":
    unittest.main()
