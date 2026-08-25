from __future__ import annotations

import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from quietward import console


class FakeStore:
    def __init__(self, _settings, *, findings=None, errors=(), defender=None, stored_coverage=None):
        self.findings = findings or []
        self.errors = errors
        self.defender = defender
        self.stored_coverage = stored_coverage
    def __enter__(self): return self
    def __exit__(self, *_args): return False
    def summary(self):
        return {"actions_executed": 0, "evidence_chain": {"valid": True}, "last_cycle": {"status": "ok", "completed_at": datetime.now(timezone.utc).isoformat(), "actions_executed": 0, "error": None}}
    def recent_findings(self, limit):
        assert limit == 500
        return self.findings
    def latest_snapshot(self):
        if not self.errors and self.defender is None: return None
        defender = SimpleNamespace(to_dict=lambda: self.defender) if self.defender is not None else None
        return SimpleNamespace(errors=self.errors, defender=defender)
    def get_metadata(self, key):
        if key != "last_coverage_report" or self.stored_coverage is None: return None
        return self.stored_coverage if isinstance(self.stored_coverage, str) else json.dumps(self.stored_coverage, sort_keys=True)


class ConsoleStatusTests(unittest.TestCase):
    def config(self, *, health_path: Path | None = None):
        value = {"storage": object()}
        if health_path is not None: value["service"] = SimpleNamespace(health_path=health_path)
        return SimpleNamespace(**value)

    @staticmethod
    def incomplete_coverage():
        return {"resolution_safe": False, "degraded_count": 1, "cycle_id": 7, "domains": [{"name": "processes", "state": "degraded", "required_for_resolution": True, "resolution_complete": False, "reason_code": "collector_error", "issue_count": 1}], "actions_executed": 0}

    def test_status_command_reports_normal(self) -> None:
        with mock.patch.object(console, "load_config", return_value=self.config()), mock.patch.object(console, "SentinelStore", side_effect=lambda settings: FakeStore(settings)), mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            code = console._run_status(["--pretty"])
        self.assertEqual(0, code); payload = json.loads(output.getvalue()); self.assertEqual("Normal", payload["status"]["label"]); self.assertEqual(0, payload["actions_executed"]); self.assertIsNone(payload["monitoring"]["coverage"])

    def test_status_command_reports_review_recommended(self) -> None:
        finding = {"severity": "high", "review": {"state": "open"}}
        with mock.patch.object(console, "load_config", return_value=self.config()), mock.patch.object(console, "SentinelStore", side_effect=lambda settings: FakeStore(settings, findings=[finding], errors=("optional collector unavailable",))), mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            code = console.main(["status", "--pretty"])
        self.assertEqual(1, code); payload = json.loads(output.getvalue()); self.assertEqual("Review recommended", payload["status"]["label"]); self.assertEqual(1, payload["status"]["active_findings"]["high"]); self.assertEqual("observe_only", payload["mode"])

    def test_status_command_reads_incomplete_service_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            health_path = Path(temporary) / "health.json"; health_path.write_text(json.dumps({"coverage": self.incomplete_coverage()}), encoding="utf-8"); config = self.config(health_path=health_path)
            with mock.patch.object(console, "load_config", return_value=config), mock.patch.object(console, "SentinelStore", side_effect=lambda settings: FakeStore(settings)), mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                code = console.main(["status", "--pretty"])
        self.assertEqual(1, code); payload = json.loads(output.getvalue()); self.assertEqual("Review recommended", payload["status"]["label"]); self.assertFalse(payload["monitoring"]["coverage"]["resolution_safe"]); self.assertEqual(payload["monitoring"]["coverage"]["cycle_id"], 7)

    def test_status_falls_back_to_database_coverage_without_health_file(self) -> None:
        stored = self.incomplete_coverage()
        with mock.patch.object(console, "load_config", return_value=self.config()), mock.patch.object(console, "SentinelStore", side_effect=lambda settings: FakeStore(settings, stored_coverage=stored)), mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            code = console.main(["status", "--pretty"])
        self.assertEqual(1, code); payload = json.loads(output.getvalue()); self.assertEqual("Review recommended", payload["status"]["label"]); self.assertEqual(payload["monitoring"]["coverage"]["cycle_id"], 7); self.assertTrue(any("will not resolve incidents" in reason for reason in payload["status"]["reasons"]))

    def test_health_coverage_overrides_older_database_coverage(self) -> None:
        stored = self.incomplete_coverage(); current = {"resolution_safe": True, "degraded_count": 0, "cycle_id": 8, "domains": [], "actions_executed": 0}
        with tempfile.TemporaryDirectory() as temporary:
            health_path = Path(temporary) / "health.json"; health_path.write_text(json.dumps({"coverage": current}), encoding="utf-8"); config = self.config(health_path=health_path)
            with mock.patch.object(console, "load_config", return_value=config), mock.patch.object(console, "SentinelStore", side_effect=lambda settings: FakeStore(settings, stored_coverage=stored)), mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                code = console.main(["status", "--pretty"])
        self.assertEqual(0, code); payload = json.loads(output.getvalue()); self.assertEqual(payload["monitoring"]["coverage"]["cycle_id"], 8); self.assertTrue(payload["monitoring"]["coverage"]["resolution_safe"])

    def test_invalid_database_coverage_is_ignored(self) -> None:
        with mock.patch.object(console, "load_config", return_value=self.config()), mock.patch.object(console, "SentinelStore", side_effect=lambda settings: FakeStore(settings, stored_coverage="{not-json")), mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            code = console.main(["status", "--pretty"])
        self.assertEqual(0, code); payload = json.loads(output.getvalue()); self.assertIsNone(payload["monitoring"]["coverage"])


if __name__ == "__main__": unittest.main()
