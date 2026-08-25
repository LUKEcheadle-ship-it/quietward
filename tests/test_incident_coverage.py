from __future__ import annotations

import unittest

from quietward.incident_coverage import incident_resolution_safe


class IncidentCoverageTests(unittest.TestCase):
    def test_socket_incident_can_resolve_while_unrelated_scanner_not_due(self) -> None:
        domains = [{"name": "listening_sockets", "state": "complete"}, {"name": "processes", "state": "complete"}, {"name": "scanner:clamav:0", "state": "not_due"}]
        self.assertTrue(incident_resolution_safe(["windows_socket_snapshot"], domains, global_resolution_safe=False))

    def test_scanner_incident_waits_for_its_scanner(self) -> None:
        domains = [{"name": "listening_sockets", "state": "complete"}, {"name": "scanner:clamav:0", "state": "not_due"}]
        self.assertFalse(incident_resolution_safe(["clamav"], domains, global_resolution_safe=False))
        domains[1]["state"] = "complete"
        self.assertTrue(incident_resolution_safe(["clamav"], domains, global_resolution_safe=False))

    def test_all_jobs_for_same_scanner_must_be_complete(self) -> None:
        domains = [{"name": "scanner:yara:0", "state": "complete"}, {"name": "scanner:yara:1", "state": "degraded"}]
        self.assertFalse(incident_resolution_safe(["yara"], domains, global_resolution_safe=False))

    def test_disabled_relevant_domain_does_not_clear_prior_incident(self) -> None:
        self.assertFalse(incident_resolution_safe(["windows_persistence_snapshot"], [{"name": "persistence", "state": "disabled"}], global_resolution_safe=True))

    def test_multi_source_incident_requires_all_relevant_domains(self) -> None:
        domains = [{"name": "processes", "state": "complete"}, {"name": "listening_sockets", "state": "degraded"}]
        self.assertFalse(incident_resolution_safe(["windows_process_snapshot", "windows_socket_snapshot"], domains, global_resolution_safe=False))

    def test_unknown_source_falls_back_to_global_decision(self) -> None:
        self.assertFalse(incident_resolution_safe(["future_collector_v9"], [], global_resolution_safe=False))
        self.assertTrue(incident_resolution_safe(["future_collector_v9"], [], global_resolution_safe=True))

    def test_sensitive_file_source_requires_active_file_coverage(self) -> None:
        self.assertTrue(incident_resolution_safe(["debian_file_integrity_snapshot"], [{"name": "sensitive_files", "state": "complete"}], global_resolution_safe=False))
        self.assertFalse(incident_resolution_safe(["debian_file_integrity_snapshot"], [{"name": "sensitive_files", "state": "disabled"}], global_resolution_safe=True))


if __name__ == "__main__":
    unittest.main()
