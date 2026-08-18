from __future__ import annotations

import unittest
from pathlib import Path

from quietward.cli import build_parser


class CLITests(unittest.TestCase):
    def test_production_commands_exist(self) -> None:
        parser = build_parser()
        self.assertEqual(parser.prog, "quietward")
        for command in ("run", "serve", "status", "doctor", "scan", "model-info"):
            args = parser.parse_args([command])
            self.assertEqual(args.command, command)

    def test_qualification_accepts_the_service_config(self) -> None:
        args = build_parser().parse_args(["qualify", "--config", "/tmp/config.json"])
        self.assertEqual(args.config, Path("/tmp/config.json"))


if __name__ == "__main__":
    unittest.main()
