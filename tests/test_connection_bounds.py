from __future__ import annotations

import unittest

from quietward.collectors.command import CONNECTIONS_COMMAND, CommandResult
from quietward.collectors.debian import (
    MAX_CONNECTION_RECORDS,
    DebianCollectorConfig,
    DebianReadOnlyCollector,
)


class ConnectionBoundTests(unittest.TestCase):
    def test_connection_snapshot_is_capped(self) -> None:
        class Runner:
            def run(self, argv):
                self.assert_command = tuple(argv)
                output = "\n".join(
                    f'tcp ESTAB 0 0 192.168.1.10:{20000 + index} 8.8.8.8:{1000 + index} users:(("app",pid={index + 1},fd=3))'
                    for index in range(MAX_CONNECTION_RECORDS + 5)
                )
                return CommandResult(tuple(argv), 0, output, "")

        runner = Runner()
        batch = DebianReadOnlyCollector(
            DebianCollectorConfig(
                sensitive_files=(),
                include_processes=False,
                include_sockets=False,
                include_connections=True,
                include_auth_journal=False,
                include_docker=False,
                include_persistence=False,
            ),
            runner=runner,
            host_id="host-test",
        ).collect()
        self.assertEqual(runner.assert_command, CONNECTIONS_COMMAND)
        self.assertEqual(len(batch.snapshot.connections), MAX_CONNECTION_RECORDS)
        self.assertEqual(batch.events, ())


if __name__ == "__main__":
    unittest.main()
