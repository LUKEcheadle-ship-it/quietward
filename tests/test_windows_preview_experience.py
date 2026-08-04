from __future__ import annotations

import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from quietward.config import DashboardSettings, StorageSettings
from quietward.dashboard import DashboardServer


class DashboardExperienceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        storage = StorageSettings(
            database_path=root / "quietward.sqlite3",
            alert_log_path=root / "alerts.jsonl",
        )
        settings = DashboardSettings(
            enabled=True,
            bind="127.0.0.1",
            port=0,
            token_file=None,
            allow_private_network_bind=False,
        )
        self.server = DashboardServer(settings, storage)
        self.server.start()
        host, port = self.server.address
        self.base = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.close()
        self.temporary.cleanup()

    def get(self, path: str) -> tuple[int, str, str]:
        with urllib.request.urlopen(self.base + path, timeout=5.0) as response:
            return (
                response.status,
                response.headers.get("Content-Type", ""),
                response.read().decode("utf-8"),
            )

    def test_dashboard_explains_attention_errors_and_zero_actions(self) -> None:
        status, content_type, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)
        self.assertIn("What needs your attention", body)
        self.assertIn("Collector health and errors", body)
        self.assertIn("Actions executed", body)
        self.assertIn("quietward diagnose --pretty", body)
        self.assertIn("QuietWard did not alter this computer", body)
        self.assertIn("Microsoft Defender evidence", body)

    def test_overview_is_read_only_and_has_usable_shape(self) -> None:
        status, content_type, body = self.get("/api/overview")
        self.assertEqual(status, 200)
        self.assertIn("application/json", content_type)
        value = json.loads(body)
        self.assertEqual(value["actions_executed"], 0)
        self.assertEqual(value["mode"], "observe_only")
        self.assertIn("summary", value)
        self.assertIn("findings", value)
        self.assertIn("events", value)
        self.assertIn("collector_errors", value)

    def test_finding_requires_an_identifier(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as captured:
            urllib.request.urlopen(
                self.base + "/api/finding",
                timeout=5.0,
            )
        self.assertEqual(captured.exception.code, 400)

    def test_dashboard_rejects_mutation_requests(self) -> None:
        request = urllib.request.Request(
            self.base + "/api/findings",
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as captured:
            urllib.request.urlopen(request, timeout=5.0)
        self.assertEqual(captured.exception.code, 405)
        payload = json.loads(captured.exception.read().decode("utf-8"))
        self.assertEqual(payload["actions_executed"], 0)


class WindowsInstallerSafetyTests(unittest.TestCase):
    def test_installer_stays_user_scoped_and_observation_only(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (root / "scripts" / "install_windows_preview.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("-RunLevel Limited", text)
        self.assertIn('bind = "127.0.0.1"', text)
        self.assertIn("execute = $false", text)
        self.assertIn("cloud_upload = $false", text)
        self.assertIn('$TaskName = "QuietWard"', text)
        self.assertIn('$QuietWardPrefix = @("-m", "quietward")', text)
        self.assertNotIn("-RunLevel Highest", text)
        self.assertNotIn('bind = "0.0.0.0"', text)

    def test_qualification_never_restarts_or_changes_the_host(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (root / "scripts" / "qualify_windows_preview.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("system_state_modified_by_qualification = $false", text)
        self.assertIn("service_restarted_by_qualification = $false", text)
        self.assertIn('qualification = "quietward-windows-preview-v1"', text)
        self.assertNotIn("Restart-Computer", text)
        self.assertNotIn("Stop-Computer", text)


if __name__ == "__main__":
    unittest.main()
