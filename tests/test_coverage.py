from __future__ import annotations

import unittest
from pathlib import Path

from quietward.config import CollectorSettings
from quietward.coverage import CoverageState, collector_coverage, complete_domain, degraded_domain, not_due_domain, report


class CoverageTests(unittest.TestCase):
    def settings(self, **overrides) -> CollectorSettings:
        values = {
            "include_processes": True,
            "include_listening_sockets": True,
            "include_outbound_connections": False,
            "include_auth_journal": True,
            "include_docker": False,
            "include_persistence": True,
            "sensitive_files": (Path("/tmp/example"),),
        }
        values.update(overrides)
        return CollectorSettings(**values)

    def test_complete_enabled_domains_allow_resolution(self) -> None:
        domains = collector_coverage(self.settings(), (), collector_version="windows-read-only-v1")
        coverage = report(domains)
        self.assertTrue(coverage.resolution_safe)
        states = {item.name: item.state for item in domains}
        self.assertEqual(states["processes"], CoverageState.COMPLETE)
        self.assertEqual(states["outbound_connections"], CoverageState.DISABLED)
        self.assertEqual(states["docker"], CoverageState.DISABLED)

    def test_required_collector_failure_blocks_resolution_without_leaking_error(self) -> None:
        secret = "C:/Users/Alice/private/location"
        coverage = report(collector_coverage(self.settings(), (f"Windows process inventory unavailable: {secret}",), collector_version="windows-read-only-v1"))
        self.assertFalse(coverage.resolution_safe)
        process = next(item for item in coverage.domains if item.name == "processes")
        self.assertEqual(process.state, CoverageState.DEGRADED)
        self.assertEqual(process.issue_count, 1)
        self.assertNotIn(secret, str(coverage.to_dict()))
        self.assertNotIn("Alice", str(coverage.to_dict()))

    def test_defender_failure_is_visible_but_does_not_block_absence_resolution(self) -> None:
        coverage = report(collector_coverage(self.settings(), ("optional Microsoft Defender status unavailable: exit code 1",), collector_version="windows-read-only-v1"))
        defender = next(item for item in coverage.domains if item.name == "microsoft_defender")
        self.assertEqual(defender.state, CoverageState.DEGRADED)
        self.assertFalse(defender.required_for_resolution)
        self.assertTrue(coverage.resolution_safe)

    def test_unclassified_warning_fails_closed(self) -> None:
        coverage = report(collector_coverage(self.settings(), ("unexpected collector warning",), collector_version="windows-read-only-v1"))
        other = next(item for item in coverage.domains if item.name == "collector_other")
        self.assertEqual(other.state, CoverageState.DEGRADED)
        self.assertTrue(other.required_for_resolution)
        self.assertFalse(coverage.resolution_safe)

    def test_not_due_scanner_blocks_global_absence_resolution(self) -> None:
        coverage = report((complete_domain("collector"), not_due_domain("scanner:clamav:0")))
        self.assertFalse(coverage.resolution_safe)
        self.assertEqual(coverage.degraded_count, 1)

    def test_optional_degraded_context_does_not_block_resolution(self) -> None:
        coverage = report((complete_domain("collector"), degraded_domain("optional_context", reason_code="unavailable", required_for_resolution=False)))
        self.assertTrue(coverage.resolution_safe)
        self.assertEqual(coverage.degraded_count, 1)


if __name__ == "__main__":
    unittest.main()
