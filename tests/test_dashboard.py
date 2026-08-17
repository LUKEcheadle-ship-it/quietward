from __future__ import annotations

import http.client
import json
import tempfile
import unittest
from pathlib import Path

from quietward.config import DashboardSettings, StorageSettings
from quietward.dashboard import (
    DashboardServer,
    finding_group_key,
    finding_sort_key,
    group_findings,
    normalize_severity,
    translate_reason,
)
from quietward.storage import SentinelStore


class DashboardTests(unittest.TestCase):
    @staticmethod
    def finding(
        identifier: str,
        *,
        title: str = "Suspicious Auto-Service Started",
        subject: str = "service:synthetic",
        severity: str = "high",
        review: str = "open",
        created_at: str = "2026-08-13T22:49:00Z",
        reasons: list[str] | None = None,
    ) -> dict[str, object]:
        return {
            "finding_id": identifier,
            "title": title,
            "subject": subject,
            "severity": severity,
            "score": 80,
            "summary": "A synthetic persistence observation.",
            "created_at": created_at,
            "reasons": reasons or ["base:persistence_change=44.0"],
            "review": {"state": review},
            "evidence_event_ids": [f"event-{identifier}"],
        }

    def test_grouping_250_findings_preserves_every_child(self) -> None:
        findings = [
            self.finding(
                f"finding-{index:03}",
                subject=f"service:synthetic-{index}",
                severity=("critical", "high", "mid", "low", "info")[index % 5],
                review=("open", "resolved", "expected")[index % 3],
            )
            for index in range(250)
        ]
        groups = group_findings(findings)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["count"], 250)
        self.assertIn("Mixed:", groups[0]["review_summary"])
        self.assertEqual(
            {item["finding_id"] for item in groups[0]["findings"]},
            {item["finding_id"] for item in findings},
        )

    def test_grouping_resists_similar_title_collisions(self) -> None:
        service = self.finding("service", subject="service:alpha")
        path = self.finding("path", subject="C:\\synthetic\\alpha")
        different_detector = self.finding(
            "model", subject="service:beta", reasons=["tiny_model_probability=0.9580"]
        )
        hashes = self.finding(
            "hash",
            title="Suspicious Auto-Service Started aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            subject="service:gamma",
        )
        self.assertEqual(finding_group_key(service), finding_group_key(hashes))
        self.assertEqual(len(group_findings([service, path, different_detector, hashes])), 3)

    def test_severity_urgency_timestamp_and_tie_order(self) -> None:
        findings = [
            self.finding("unknown", severity="novel"),
            self.finding("info", severity="info"),
            self.finding("low", severity="low"),
            self.finding("medium", severity="medium"),
            self.finding("mid", severity="mid"),
            self.finding("high-resolved", severity="high", review="resolved", created_at="2026-08-14T00:00:00Z"),
            self.finding("high-open-old", severity="high", created_at="2026-08-12T00:00:00Z"),
            self.finding("high-open-new", severity="high", created_at="2026-08-13T00:00:00+00:00"),
            self.finding("critical", severity="critical", created_at="invalid"),
        ]
        ordered = sorted(findings, key=finding_sort_key)
        self.assertEqual(ordered[0]["finding_id"], "critical")
        self.assertEqual([item["finding_id"] for item in ordered[1:4]], ["high-open-new", "high-open-old", "high-resolved"])
        self.assertEqual({item["finding_id"] for item in ordered[4:6]}, {"medium", "mid"})
        self.assertEqual(ordered[-1]["finding_id"], "unknown")
        self.assertEqual(normalize_severity("mid"), "medium")

    def test_dashboard_contains_accessible_safe_refresh_ui(self) -> None:
        html = DashboardServer._html()
        self.assertLess(html.index("How to use QuietWard"), html.index("What needs your attention"))
        self.assertIn('<details class="group"', html)
        self.assertIn("Raw Event Log", html)
        self.assertIn("if(state.loading)return false", html)
        self.assertIn("Previously displayed data was preserved", html)
        self.assertIn("localStorage", html)
        self.assertIn("aria-live=\"polite\"", html)
        self.assertIn("f.reason_explanations||f.reasons", html)

    def test_reason_translation_is_allowlisted_and_safe(self) -> None:
        self.assertEqual(translate_reason("tiny_model_probability=0.9580"), "The local model assigned this event a 95.8% risk score.")
        self.assertEqual(translate_reason("base:persistence_change=44.0"), "QuietWard detected a persistence-related system change.")
        for raw in ("tiny_model_probability=9", "tiny_model_probability=-1", "tiny_model_probability=malformed", "unknown=value", "<script>alert(1)</script>"):
            self.assertEqual(translate_reason(raw), raw)

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
