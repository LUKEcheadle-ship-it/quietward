from __future__ import annotations

import unittest
from datetime import datetime, timezone

from quietward.contracts import EventKind, SecurityEvent


class SecurityEventContractTests(unittest.TestCase):
    def test_rejects_invalid_confidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "confidence"):
            SecurityEvent(
                event_id="evt",
                observed_at=datetime.now(timezone.utc),
                host_id="host",
                source="test",
                kind=EventKind.PROCESS_START,
                subject="process",
                confidence=1.1,
            )

    def test_round_trip_dictionary(self) -> None:
        event = SecurityEvent.from_dict(
            {
                "event_id": "evt",
                "observed_at": "2026-07-30T16:00:00Z",
                "host_id": "host",
                "source": "test",
                "kind": "file_change",
                "subject": "/tmp/a",
                "attributes": {"x": 1},
                "confidence": 0.8,
            }
        )
        self.assertEqual(event.kind, EventKind.FILE_CHANGE)
        self.assertEqual(event.to_dict()["observed_at"], "2026-07-30T16:00:00Z")


if __name__ == "__main__":
    unittest.main()
