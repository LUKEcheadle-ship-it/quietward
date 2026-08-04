from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quietward.collectors.command import CONNECTIONS_COMMAND, CommandResult, ReadOnlyCommandRunner
from quietward.collectors.debian import DebianCollectorConfig, DebianReadOnlyCollector
from quietward.collectors.diff import diff_snapshots
from quietward.collectors.models import CollectorSnapshot
from quietward.collectors.parsers import parse_connections_output
from quietward.config import QuietWardConfig
from quietward.contracts import EventKind

NOW = datetime(2026, 7, 31, 15, 0, tzinfo=timezone.utc)


class ConnectionTests(unittest.TestCase):
    def test_exact_connection_command_is_allowlisted(self) -> None:
        self.assertEqual(ReadOnlyCommandRunner.validate(CONNECTIONS_COMMAND), CONNECTIONS_COMMAND)

    def test_parser_hashes_remote_addresses(self) -> None:
        remote = "203.0.113.44"
        rows = parse_connections_output(
            f'tcp ESTAB 0 0 192.168.1.10:55000 {remote}:443 users:(("curl",pid=22,fd=3))\n'
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].remote_port, 443)
        self.assertEqual(rows[0].process_name, "curl")
        self.assertNotIn(remote, json.dumps(rows[0].to_dict()))
        self.assertFalse(rows[0].to_dict()["raw_remote_address_persisted"])

    def test_scope_classification(self) -> None:
        rows = parse_connections_output("\n".join([
            'tcp ESTAB 0 0 127.0.0.1:5000 127.0.0.1:8000 users:(("python",pid=1,fd=3))',
            'tcp ESTAB 0 0 192.168.1.10:5001 10.0.0.2:443 users:(("app",pid=2,fd=3))',
            'tcp ESTAB 0 0 192.168.1.10:5002 8.8.8.8:53 users:(("dns",pid=3,fd=3))',
        ]))
        self.assertEqual({row.destination_scope for row in rows}, {"private", "public", "loopback"})

    def test_first_snapshot_is_silent_and_new_connection_emits_event(self) -> None:
        first_connection = parse_connections_output('tcp ESTAB 0 0 192.168.1.10:5000 10.0.0.2:443 users:(("app",pid=2,fd=3))')
        second_connection = parse_connections_output('tcp ESTAB 0 0 192.168.1.10:5001 8.8.8.8:53 users:(("dns",pid=3,fd=3))')
        first = CollectorSnapshot(NOW, "host-a", connections=first_connection)
        second = CollectorSnapshot(NOW + timedelta(minutes=1), "host-a", connections=(*first_connection, *second_connection))
        self.assertEqual(diff_snapshots(first, None), [])
        events = diff_snapshots(second, first)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.kind, EventKind.OUTBOUND_CONNECTION)
        self.assertEqual(event.attributes["destination_scope"], "public")
        self.assertTrue(event.attributes["external_destination"])
        serialized = json.dumps(event.to_dict())
        self.assertNotIn("8.8.8.8", serialized)
        self.assertFalse(event.attributes["raw_remote_address_persisted"])

    def test_collector_executes_connection_command_only_when_enabled(self) -> None:
        class Runner:
            def __init__(self) -> None:
                self.calls = []

            def run(self, argv):
                key = tuple(argv)
                self.calls.append(key)
                return CommandResult(key, 0, 'tcp ESTAB 0 0 192.168.1.10:5002 8.8.8.8:53 users:(("dns",pid=3,fd=3))', '')

        disabled_runner = Runner()
        disabled = DebianReadOnlyCollector(
            DebianCollectorConfig(sensitive_files=(), include_processes=False, include_sockets=False, include_connections=False, include_auth_journal=False, include_docker=False, include_persistence=False),
            runner=disabled_runner,
            host_id="host-a",
        ).collect()
        self.assertEqual(disabled_runner.calls, [])
        self.assertEqual(disabled.snapshot.connections, ())

        enabled_runner = Runner()
        enabled = DebianReadOnlyCollector(
            DebianCollectorConfig(sensitive_files=(), include_processes=False, include_sockets=False, include_connections=True, include_auth_journal=False, include_docker=False, include_persistence=False),
            runner=enabled_runner,
            host_id="host-a",
        ).collect()
        self.assertEqual(enabled_runner.calls, [CONNECTIONS_COMMAND])
        self.assertEqual(len(enabled.snapshot.connections), 1)
        self.assertEqual(enabled.events, ())

    def test_connection_monitoring_is_opt_in_and_raw_destinations_are_forbidden(self) -> None:
        state = str(Path(tempfile.gettempdir()) / "quietward-connections")
        config = QuietWardConfig.from_dict({"state_dir": state})
        self.assertFalse(config.collector.include_outbound_connections)
        enabled = QuietWardConfig.from_dict({"state_dir": state, "collector": {"include_outbound_connections": True}})
        self.assertTrue(enabled.collector.include_outbound_connections)
        with self.assertRaises(ValueError):
            QuietWardConfig.from_dict({"state_dir": state, "collector": {"persist_raw_destination_addresses": True}})

    def test_old_snapshot_without_connections_still_loads(self) -> None:
        old = {
            "collector_version": "debian-read-only-v2",
            "observed_at": "2026-07-31T15:00:00Z",
            "host_id": "host-a",
            "processes": [], "sockets": [], "containers": [], "files": [],
            "persistence": [], "errors": [],
        }
        snapshot = CollectorSnapshot.from_dict(old)
        self.assertEqual(snapshot.connections, ())


if __name__ == "__main__":
    unittest.main()
