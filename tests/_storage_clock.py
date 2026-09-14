"""Clock for August storage fixtures; real expiry remains covered separately."""
from datetime import datetime, timezone
import unittest
from unittest.mock import patch


class FixtureDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        value = cls(2026, 8, 20, 12, tzinfo=timezone.utc)
        return value.astimezone(tz) if tz is not None else value.replace(tzinfo=None)


class StorageClockTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        clock = patch("quietward.storage.datetime", FixtureDateTime)
        clock.start()
        self.addCleanup(clock.stop)
