from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from quietward.collectors.diff import diff_snapshots
from quietward.collectors.models import (
    CollectorSnapshot,
    FileRecord,
    ProcessRecord,
    SocketRecord,
)
from quietward.contracts import EventKind


class SnapshotDiffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime.now(timezone.utc)
        self.previous = CollectorSnapshot(
            observed_at=self.now - timedelta(minutes=1),
            host_id="host-test",
            processes=(),
            sockets=(SocketRecord("tcp", "127.0.0.1", 22, "sshd"),),
            files=(
                FileRecord(
                    "/etc/ssh/sshd_config",
                    True,
                    "regular",
                    420,
                    10,
                    1,
                    "old",
                ),
            ),
        )

    def test_first_snapshot_establishes_baseline(self) -> None:
        self.assertEqual(diff_snapshots(self.previous, None), [])

    def test_changes_generate_bounded_events(self) -> None:
        current = CollectorSnapshot(
            observed_at=self.now,
            host_id="host-test",
            processes=(
                ProcessRecord(
                    99,
                    1,
                    "root",
                    "xmrig",
                    "/tmp/xmrig",
                    "hash",
                    ("cryptominer_indicator", "volatile_directory_executable"),
                ),
            ),
            sockets=(
                SocketRecord("tcp", "127.0.0.1", 22, "sshd"),
                SocketRecord("tcp", "0.0.0.0", 4444, "xmrig"),
            ),
            files=(
                FileRecord(
                    "/etc/ssh/sshd_config",
                    True,
                    "regular",
                    438,
                    12,
                    2,
                    "new",
                ),
            ),
        )
        events = diff_snapshots(current, self.previous)
        kinds = {event.kind for event in events}
        self.assertEqual(
            kinds,
            {
                EventKind.PROCESS_START,
                EventKind.NEW_LISTENING_PORT,
                EventKind.SENSITIVE_FILE_CHANGE,
            },
        )
        self.assertTrue(
            all(
                event.attributes.get("baseline_deviation") == 1.0
                for event in events
            )
        )

    def test_cross_host_baseline_rejected(self) -> None:
        current = CollectorSnapshot(
            observed_at=self.now,
            host_id="another-host",
        )
        with self.assertRaisesRegex(ValueError, "host_id mismatch"):
            diff_snapshots(current, self.previous)

    def test_process_burst_requires_bounded_parent_fanout(self) -> None:
        processes = tuple(ProcessRecord(100 + index, 42, "user-hash", "sleep", "sleep", f"args-{index}") for index in range(8))
        current = CollectorSnapshot(observed_at=self.now, host_id="host-test", processes=processes)
        events = diff_snapshots(current, self.previous)
        burst = [event for event in events if event.kind is EventKind.PROCESS_BURST]
        self.assertEqual(len(burst), 1)
        self.assertEqual(burst[0].attributes["process_count"], 8)
        self.assertEqual(burst[0].attributes["parent_child_count"], 8)
        self.assertGreater(burst[0].attributes["window_seconds"], 0)
        self.assertFalse(burst[0].attributes["raw_arguments_persisted"])

    def test_small_or_unrelated_processes_do_not_trigger_burst(self) -> None:
        small = tuple(ProcessRecord(200 + index, 42, "user-hash", "bash", "bash", f"args-{index}") for index in range(3))
        spread = tuple(ProcessRecord(300 + index, index, "user-hash", "make", "make", f"args-{index}") for index in range(8))
        for processes in (small, spread):
            current = CollectorSnapshot(observed_at=self.now, host_id="host-test", processes=processes)
            self.assertNotIn(EventKind.PROCESS_BURST, {event.kind for event in diff_snapshots(current, self.previous)})

    def test_encoded_shell_chain_is_a_redacted_execution_finding(self) -> None:
        process = ProcessRecord(700, 42, "user-hash", "bash", "bash", "opaque-args", ("encoded_shell_chain",))
        current = CollectorSnapshot(observed_at=self.now, host_id="host-test", processes=(process,))
        event = diff_snapshots(current, self.previous)[0]
        self.assertEqual(event.kind, EventKind.ENCODED_COMMAND)
        self.assertTrue(event.attributes["encoded_argument_detected"])
        self.assertEqual(event.attributes["encoding_style"], "base64-like")
        self.assertFalse(event.attributes["raw_arguments_persisted"])

    def test_normal_shell_and_python_do_not_create_encoded_event(self) -> None:
        processes = (ProcessRecord(701, 42, "user-hash", "bash", "bash", "normal"), ProcessRecord(702, 42, "user-hash", "python3", "python3", "normal"))
        current = CollectorSnapshot(observed_at=self.now, host_id="host-test", processes=processes)
        self.assertNotIn(EventKind.ENCODED_COMMAND, {item.kind for item in diff_snapshots(current, self.previous)})


if __name__ == "__main__":
    unittest.main()
