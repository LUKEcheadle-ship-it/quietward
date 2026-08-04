from __future__ import annotations

import http.client
import json
import tempfile
import unittest
from pathlib import Path

from quietward.config import DashboardSettings, StorageSettings
from quietward.dashboard import DashboardServer
from quietward.storage import SentinelStore


class DashboardTests(unittest.TestCase):
    def test_public_bind_rejected(self) -> None:
        storage = StorageSettings(Path("/tmp/db"), Path("/tmp/alerts"))
        with self.assertRaisesRegex(ValueError, "loopback"):
            DashboardServer(DashboardSettings(bind="0.0.0.0", port=8765), storage)

    def test_read_only_api_and_security_headers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            storage = StorageSettings(root / "db.sqlite", root / "alerts.jsonl")
            with SentinelStore(storage):
                pass
            server = DashboardServer(DashboardSettings(bind="127.0.0.1", port=0), storage)
            server.start()
            try:
                connection = http.client.HTTPConnection(*server.address, timeout=2)
                connection.request("GET", "/api/summary")
                response = connection.getresponse()
                data = json.loads(response.read())
                self.assertEqual(response.status, 200)
                self.assertEqual(data["actions_executed"], 0)
                self.assertEqual(response.getheader("X-Frame-Options"), "DENY")
                connection.request("POST", "/api/findings")
                response = connection.getresponse()
                response.read()
                self.assertEqual(response.status, 405)
            finally:
                server.close()


if __name__ == "__main__":
    unittest.main()
