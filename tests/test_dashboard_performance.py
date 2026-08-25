from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import StorageSettings
from quietward.contracts import EventKind, SecurityEvent
from quietward.dashboard_performance import cached_evidence_status, fast_overview, install_dashboard_performance
from quietward.enhanced_dashboard import QuietWardDashboardServer
from quietward.performance_store import PerformanceSentinelStore
from quietward.pipeline import SentinelPipeline
from quietward.storage import SentinelStore


class DashboardPerformanceTests(unittest.TestCase):
    def settings(self, root: Path) -> StorageSettings:
        return StorageSettings(database_path=root / "quietward.sqlite3", alert_log_path=root / "alerts.jsonl")

    def test_recent_cached_verification_avoids_full_dashboard_recheck(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); settings = self.settings(root)
            with PerformanceSentinelStore(settings) as performance_store:
                verified = performance_store.verify_evidence_chain(); self.assertTrue(verified["valid"])
                raw = performance_store.get_metadata("last_evidence_verification_report"); self.assertIsNotNone(raw); cached_payload = json.loads(raw); self.assertNotIn("signature_key_id", cached_payload)
            with SentinelStore(settings) as store:
                with mock.patch.object(store, "verify_evidence_chain", side_effect=AssertionError("full verifier should not run")):
                    status = cached_evidence_status(store); overview = fast_overview(store, 10)
            self.assertTrue(status["valid"]); self.assertTrue(status["cached_for_dashboard"]); self.assertTrue(overview["summary"]["evidence_chain"]["cached_for_dashboard"]); self.assertEqual(overview["actions_executed"], 0)

    def test_chain_head_change_invalidates_recent_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); settings = self.settings(root)
            with PerformanceSentinelStore(settings) as performance_store: performance_store.verify_evidence_chain()
            with SentinelStore(settings) as store:
                now = datetime.now(timezone.utc); event = SecurityEvent("event-dashboard-cache", now, "host", "test", EventKind.FILE_CHANGE, "subject"); report = SentinelPipeline().analyze([event])
                store.persist_cycle(CollectionBatch(CollectorSnapshot(now, "host"), (event,)), report, started_at=now, completed_at=now)
                with mock.patch.object(store, "verify_evidence_chain", return_value={"valid": True, "cycles_checked": 1, "last_chain_hash": "verified-current-head", "errors": [], "cryptographically_signed": False}) as verifier:
                    status = cached_evidence_status(store)
                verifier.assert_called_once(); self.assertFalse(status["cached_for_dashboard"])

    def test_stale_cache_falls_back_to_authoritative_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); settings = self.settings(root)
            with SentinelStore(settings) as store:
                stale = {"valid": True, "cycles_checked": 0, "verification_mode": "incremental", "observed_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(), "actions_executed": 0}
                with store.connection: store.set_metadata("last_evidence_verification_report", json.dumps(stale))
                with mock.patch.object(store, "verify_evidence_chain", return_value={"valid": True, "cycles_checked": 0, "errors": [], "cryptographically_signed": False}) as verifier:
                    status = cached_evidence_status(store)
                verifier.assert_called_once(); self.assertFalse(status["cached_for_dashboard"])

    def test_runtime_dashboard_polls_once_per_minute(self) -> None:
        install_dashboard_performance(); html = QuietWardDashboardServer._html()
        self.assertIn("setInterval(refresh,60000)", html); self.assertNotIn("setInterval(refresh,15000)", html); self.assertIn("/api/overview?limit=100", html); self.assertNotIn("/api/overview?limit=200", html); self.assertIn("QuietWard", html)


if __name__ == "__main__": unittest.main()
