from __future__ import annotations

import os
import unittest

from quietward.process_metrics import process_resource_snapshot


class ProcessMetricTests(unittest.TestCase):
    def test_snapshot_reports_only_self_resource_fields(self) -> None:
        value = process_resource_snapshot()
        self.assertEqual(set(value), {"rss_bytes", "rss_mib", "actions_executed"})
        self.assertEqual(value["actions_executed"], 0)
        if value["rss_bytes"] is not None:
            self.assertGreaterEqual(value["rss_bytes"], 0)
            self.assertGreaterEqual(value["rss_mib"], 0.0)

    @unittest.skipUnless(os.name == "nt", "requires native Windows process APIs")
    def test_windows_release_measurement_reports_rss(self) -> None:
        value = process_resource_snapshot()
        self.assertIsNotNone(value["rss_bytes"])
        self.assertIsNotNone(value["rss_mib"])
        self.assertGreater(value["rss_bytes"], 0)
        self.assertGreater(value["rss_mib"], 0.0)


if __name__ == "__main__":
    unittest.main()
