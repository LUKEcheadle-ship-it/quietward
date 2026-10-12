"""Real loopback HTTP regression checks using disposable synthetic state only."""
from __future__ import annotations

import http.client
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from quietward.collectors.models import CollectionBatch, CollectorSnapshot
from quietward.config import DashboardSettings, StorageSettings
from quietward.contracts import EventKind, SecurityEvent
from quietward.enhanced_dashboard import QuietWardDashboardServer
from quietward.pipeline import SentinelPipeline
from quietward.storage import SentinelStore


class ReviewDashboardHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="quietward-http-review-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.storage = StorageSettings(self.root / "review.sqlite3", self.root / "alerts.jsonl")
        self.token = "synthetic-dashboard-review-token-not-for-production"
        token_file = self.root / "dashboard.token"
        token_file.write_text(self.token, encoding="utf-8")
        token_file.chmod(0o600)
        now = datetime.now(timezone.utc)
        event = SecurityEvent(
            "synthetic-http-finding", now, "synthetic-review-host", "synthetic-review",
            EventKind.MALWARE_SIGNATURE, "/synthetic/review-only.bin",
            attributes={"known_bad_hash": True, "synthetic": True}, confidence=1.0,
        )
        snapshot = CollectorSnapshot(now, "synthetic-review-host", errors=("synthetic collector unavailable",))
        with SentinelStore(self.storage) as store:
            store.persist_cycle(
                CollectionBatch(snapshot, (event,)), SentinelPipeline().analyze([event]),
                started_at=now, completed_at=now,
            )
            store.set_metadata("last_coverage_report", json.dumps({
                "resolution_safe": False, "degraded_count": 1, "actions_executed": 0,
                "domains": [{"name": "processes", "state": "degraded", "resolution_complete": False,
                             "required_for_resolution": True, "reason_code": "collector_error"}],
            }))
            store.connection.commit()
        self.server = QuietWardDashboardServer(
            DashboardSettings(bind="127.0.0.1", port=0, token_file=token_file), self.storage,
        )
        self.server.start()
        self.addCleanup(self.server.close)

    def request(self, path: str, method: str = "GET", *, authenticated: bool = True):
        connection = http.client.HTTPConnection(*self.server.address, timeout=3)
        try:
            headers = {"Authorization": "Bearer " + self.token} if authenticated else {}
            connection.request(method, path, headers=headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_overview_retains_finding_and_missing_collector_warning(self) -> None:
        status, headers, raw = self.request("/api/overview")
        self.assertEqual(status, 200)
        payload = json.loads(raw)
        self.assertEqual(payload["mode"], "observe_only")
        self.assertEqual(payload["dashboard_mode"], "read_only")
        self.assertEqual(payload["actions_executed"], 0)
        self.assertGreater(len(payload["findings"]), 0)
        self.assertEqual(payload["collector_errors"], ["synthetic collector unavailable"])
        self.assertFalse(payload["coverage"]["resolution_safe"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")

    def test_enhanced_endpoints_require_authentication(self) -> None:
        for path in ("/api/overview", "/api/coverage", "/api/lifecycle", "/api/incidents", "/api/retention"):
            with self.subTest(path=path):
                denied, _, raw = self.request(path, authenticated=False)
                self.assertEqual(denied, 401)
                self.assertEqual(json.loads(raw)["actions_executed"], 0)
                allowed, _, _ = self.request(path)
                self.assertEqual(allowed, 200)

    def test_mutation_methods_are_refused_and_evidence_unchanged(self) -> None:
        with SentinelStore(self.storage) as store:
            before = (store.summary()["events"], store.summary()["findings"])
        for method in ("POST", "PUT", "DELETE"):
            with self.subTest(method=method):
                status, _, _ = self.request("/api/incidents", method)
                self.assertEqual(status, 405)
        with SentinelStore(self.storage) as store:
            after = (store.summary()["events"], store.summary()["findings"])
            self.assertEqual(after, before)
            self.assertEqual(store.summary()["actions_executed"], 0)

    def test_degraded_coverage_is_not_reported_as_complete(self) -> None:
        status, _, raw = self.request("/api/coverage")
        self.assertEqual(status, 200)
        coverage = json.loads(raw)["coverage"]
        self.assertFalse(coverage["resolution_safe"])
        self.assertEqual(coverage["degraded_count"], 1)
        self.assertFalse(coverage["domains"][0]["resolution_complete"])


if __name__ == "__main__":
    unittest.main()
