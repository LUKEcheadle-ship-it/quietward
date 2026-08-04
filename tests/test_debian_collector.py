from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quietward.collectors.command import DOCKER_PS_COMMAND, JOURNAL_AUTH_COMMAND, PS_COMMAND, SS_COMMAND, CommandResult
from quietward.collectors.debian import DebianCollectorConfig, DebianReadOnlyCollector
from quietward.collectors.models import CollectorSnapshot, FileRecord, SocketRecord
from quietward.pipeline import SentinelPipeline


class FakeRunner:
    def __init__(self, outputs: dict[tuple[str, ...], CommandResult]) -> None:
        self.outputs = outputs
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv):
        key = tuple(argv)
        self.calls.append(key)
        return self.outputs[key]


class DebianCollectorTests(unittest.TestCase):
    def test_collection_is_read_only_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            monitored = Path(directory) / "config"
            monitored.write_text("new", encoding="utf-8")
            journal = "\n".join([
                json.dumps({"MESSAGE": "Failed password for admin from 198.51.100.8"}),
                json.dumps({"MESSAGE": "Failed password for admin from 198.51.100.8"}),
            ])
            runner = FakeRunner({
                PS_COMMAND: CommandResult(PS_COMMAND, 0, "10 1 root xmrig /tmp/xmrig --url stratum+tcp://pool\n", ""),
                SS_COMMAND: CommandResult(SS_COMMAND, 0, 'tcp LISTEN 0 128 0.0.0.0:4444 0.0.0.0:* users:(("xmrig",pid=10,fd=3))\n', ""),
                DOCKER_PS_COMMAND: CommandResult(DOCKER_PS_COMMAND, 0, json.dumps({"ID": "abc", "Image": "test:latest", "Names": "test", "Status": "Up"}), ""),
                JOURNAL_AUTH_COMMAND: CommandResult(JOURNAL_AUTH_COMMAND, 0, journal, ""),
            })
            previous = CollectorSnapshot(
                observed_at=datetime.now(timezone.utc) - timedelta(minutes=1),
                host_id="host-test",
                sockets=(SocketRecord("tcp", "127.0.0.1", 22, "sshd"),),
                files=(FileRecord(str(monitored), True, "regular", 420, 3, 1, "old"),),
            )
            collector = DebianReadOnlyCollector(
                config=DebianCollectorConfig(sensitive_files=(monitored,)),
                runner=runner,
                host_id="host-test",
            )
            batch = collector.collect(previous)
            output = json.dumps(batch.to_dict())
            self.assertNotIn("198.51.100.8", output)
            self.assertNotIn("stratum+tcp://pool", output)
            self.assertEqual(set(runner.calls), {PS_COMMAND, SS_COMMAND, DOCKER_PS_COMMAND, JOURNAL_AUTH_COMMAND})
            report = SentinelPipeline().analyze(list(batch.events))
            self.assertEqual(report.actions_executed, 0)
            self.assertGreaterEqual(len(batch.events), 4)

    def test_missing_optional_tools_do_not_abort(self) -> None:
        runner = FakeRunner({
            PS_COMMAND: CommandResult(PS_COMMAND, 0, "", ""),
            SS_COMMAND: CommandResult(SS_COMMAND, 0, "", ""),
            DOCKER_PS_COMMAND: CommandResult(DOCKER_PS_COMMAND, 127, "", "command unavailable: docker"),
            JOURNAL_AUTH_COMMAND: CommandResult(JOURNAL_AUTH_COMMAND, 127, "", "command unavailable: journalctl"),
        })
        collector = DebianReadOnlyCollector(
            config=DebianCollectorConfig(sensitive_files=(), include_persistence=False),
            runner=runner,
            host_id="host-test",
        )
        batch = collector.collect()
        self.assertEqual(batch.events, ())
        self.assertEqual(len(batch.snapshot.errors), 2)


if __name__ == "__main__":
    unittest.main()
