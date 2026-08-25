from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from quietward.user_status import assess_user_status

NOW = datetime(2026, 8, 6, 16, 0, tzinfo=timezone.utc)
def summary(**overrides):
    value = {"actions_executed": 0, "evidence_chain": {"valid": True}, "last_cycle": {"status": "ok", "completed_at": (NOW - timedelta(seconds=30)).isoformat(), "actions_executed": 0, "error": None}}; value.update(overrides); return value
def finding(severity: str, state: str = "open"): return {"severity": severity, "review": {"state": state}}

class UserStatusTests(unittest.TestCase):
    def test_normal_when_current_and_clear(self) -> None:
        result = assess_user_status(summary(), [], now=NOW); self.assertEqual("normal", result.level); self.assertEqual("Normal", result.label); self.assertEqual(0, result.to_dict()["actions_executed"])
    def test_invalid_evidence_is_urgent(self) -> None:
        result = assess_user_status(summary(evidence_chain={"valid": False}), [], now=NOW); self.assertEqual("urgent", result.level); self.assertTrue(any("integrity" in item for item in result.reasons))
    def test_active_critical_is_urgent(self) -> None:
        result = assess_user_status(summary(), [finding("critical")], now=NOW); self.assertEqual("urgent", result.level); self.assertEqual(1, result.active_critical)
    def test_resolved_critical_does_not_raise_status(self) -> None: self.assertEqual("normal", assess_user_status(summary(), [finding("critical", "resolved")], now=NOW).level)
    def test_high_and_medium_findings_recommend_review(self) -> None:
        result = assess_user_status(summary(), [finding("high"), finding("medium")], now=NOW); self.assertEqual("review_recommended", result.level); self.assertEqual(1, result.active_high); self.assertEqual(1, result.active_medium)
    def test_collector_warning_recommends_review(self) -> None: self.assertEqual("review_recommended", assess_user_status(summary(), [], collector_errors=("collector unavailable",), now=NOW).level)
    def test_incomplete_coverage_recommends_review(self) -> None:
        result = assess_user_status(summary(), [], coverage={"resolution_safe": False, "operationally_healthy": False, "degraded_required": 2, "degraded_count": 2, "domains": []}, now=NOW); self.assertEqual("review_recommended", result.level); self.assertTrue(any("2 required observation domains" in item for item in result.reasons)); self.assertTrue(any("will not resolve incidents" in item for item in result.reasons))
    def test_scheduled_not_due_domains_remain_normal(self) -> None: self.assertEqual("normal", assess_user_status(summary(), [], coverage={"resolution_safe": False, "operationally_healthy": True, "scheduled_not_due": 3, "degraded_required": 0, "degraded_count": 3, "domains": []}, now=NOW).level)
    def test_resolution_safe_coverage_does_not_change_normal_status(self) -> None: self.assertEqual("normal", assess_user_status(summary(), [], coverage={"resolution_safe": True, "operationally_healthy": True, "degraded_count": 1, "domains": []}, now=NOW).level)
    def test_stale_monitoring_recommends_review(self) -> None:
        stale = summary(last_cycle={"status": "ok", "completed_at": (NOW - timedelta(minutes=10)).isoformat(), "actions_executed": 0, "error": None}); result = assess_user_status(stale, [], now=NOW, stale_after_seconds=300); self.assertEqual("review_recommended", result.level); self.assertTrue(any("older" in item for item in result.reasons))
    def test_missing_cycle_recommends_review(self) -> None: self.assertEqual("review_recommended", assess_user_status(summary(last_cycle=None), [], now=NOW).level)
    def test_active_defender_threat_is_urgent(self) -> None:
        result = assess_user_status(summary(), [], defender={"active_threat_count": 1, "antivirus_enabled": True, "real_time_protection_enabled": True}, now=NOW); self.assertEqual("urgent", result.level); self.assertTrue(any("Defender" in item for item in result.reasons))
    def test_disabled_defender_recommends_review(self) -> None: self.assertEqual("review_recommended", assess_user_status(summary(), [], defender={"active_threat_count": 0, "antivirus_enabled": False, "real_time_protection_enabled": False}, now=NOW).level)
    def test_bad_freshness_configuration_is_rejected(self) -> None:
        with self.assertRaises(ValueError): assess_user_status(summary(), [], now=NOW, stale_after_seconds=0)

if __name__ == "__main__": unittest.main()
