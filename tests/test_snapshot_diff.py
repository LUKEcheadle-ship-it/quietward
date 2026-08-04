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


if __name__ == "__main__":
    unittest.main()
