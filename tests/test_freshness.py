from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from quietward.config import ScannerJobSettings
from quietward.freshness import ScannerFreshnessInspector


class FreshnessTests(unittest.TestCase):
    def test_fresh_rules_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            rules = Path(temporary) / "rules.yar"
            rules.write_text("rule test { condition: false }")
            inspector = ScannerFreshnessInspector(now=lambda: datetime.now(timezone.utc))
            job = ScannerJobSettings("yara", True, 60, 5, targets=(Path("/tmp"),), rules_path=rules, max_data_age_hours=24)
            status = inspector.inspect(job)
            self.assertTrue(status.data_present)
            self.assertFalse(status.stale)

    def test_missing_enabled_data_emits_weakness(self) -> None:
        inspector = ScannerFreshnessInspector()
        job = ScannerJobSettings("debsecan", True, 60, 5, data_source=Path("/does/not/exist"))
        status = inspector.inspect(job)
        self.assertTrue(status.stale)
        event = inspector.event(job, "host")
        self.assertIsNotNone(event)
        self.assertFalse(event.attributes["network_update_performed"])


if __name__ == "__main__":
    unittest.main()
