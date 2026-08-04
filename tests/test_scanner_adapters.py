from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from quietward.contracts import EventKind
from quietward.pipeline import SentinelPipeline
from quietward.scanners import (
    parse_clamav_output,
    parse_debsecan_simple,
    parse_trivy_json,
    parse_yara_output,
)


class ScannerAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 30, 18, 0, tzinfo=timezone.utc)

    def test_clamav_positive_detection(self) -> None:
        events = parse_clamav_output(
            "/tmp/eicar.com: Win.Test.EICAR_HDB-1 FOUND\n----------- SCAN SUMMARY -----------\n",
            "host-test",
            observed_at=self.now,
            scanner_exit_code=1,
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, EventKind.MALWARE_SIGNATURE)
        self.assertEqual(events[0].attributes["signature"], "Win.Test.EICAR_HDB-1")
        self.assertFalse(events[0].attributes["raw_scanner_output_persisted"])

    def test_yara_deduplicates_rules_and_omits_strings(self) -> None:
        events = parse_yara_output(
            "Suspicious_PowerShell /tmp/file\n0x10:$a: secret-string\nSuspicious_PowerShell /tmp/file\n",
            "host-test",
            "/tmp/file",
            observed_at=self.now,
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].attributes["rule"], "Suspicious_PowerShell")
        self.assertNotIn("secret-string", json.dumps(events[0].to_dict()))

    def test_trivy_json_normalizes_vulnerability(self) -> None:
        report = {
            "SchemaVersion": 2,
            "ArtifactName": "debian:12",
            "Results": [{
                "Target": "debian:12 (debian 12.5)",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2026-1234",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.1",
                    "FixedVersion": "3.0.2",
                    "Severity": "HIGH",
                    "SeveritySource": "debian",
                    "Title": "Example vulnerability",
                    "CVSS": {"nvd": {"V3Score": 8.1}},
                    "Description": "do not persist this description",
                    "References": ["https://example.invalid"],
                }],
            }],
        }
        events = parse_trivy_json(json.dumps(report), "host-test", observed_at=self.now)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.kind, EventKind.PACKAGE_VULNERABILITY)
        self.assertEqual(event.attributes["cvss"], 8.1)
        self.assertTrue(event.attributes["fix_available"])
        serialized = json.dumps(event.to_dict())
        self.assertNotIn("do not persist", serialized)
        self.assertNotIn("example.invalid", serialized)

    def test_debsecan_simple_creates_package_events(self) -> None:
        events = parse_debsecan_simple(
            "CVE-2026-1111 openssl libssl3\ninvalid row\n",
            "host-test",
            observed_at=self.now,
            suite="bookworm",
        )
        self.assertEqual({item.subject for item in events}, {"package:openssl", "package:libssl3"})
        self.assertTrue(all(item.attributes["source_package_mapping_caveat"] for item in events))

    def test_scanner_events_remain_observation_only(self) -> None:
        events = parse_clamav_output("/tmp/x: Test.Signature FOUND\n", "host-test", observed_at=self.now)
        report = SentinelPipeline().analyze(events)
        self.assertEqual(report.actions_executed, 0)
        self.assertTrue(all(not proposal.executable_in_current_mode for proposal in report.action_proposals))

    def test_invalid_trivy_json_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid Trivy JSON"):
            parse_trivy_json("not-json", "host-test")


if __name__ == "__main__":
    unittest.main()
