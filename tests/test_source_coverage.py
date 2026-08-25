from __future__ import annotations

import unittest

from quietward.incident_coverage import incident_resolution_safe


class SourceCoverageTests(unittest.TestCase):
    def test_real_auth_sources_use_authentication_domain(self) -> None:
        for source in ("journald_ssh_read_only", "windows_security_log_read_only"):
            self.assertTrue(incident_resolution_safe([source], [{"name": "authentication", "state": "complete"}, {"name": "scanner:clamav:0", "state": "not_due"}], global_resolution_safe=False))
            self.assertFalse(incident_resolution_safe([source], [{"name": "authentication", "state": "not_due"}], global_resolution_safe=True))

    def test_real_docker_sources_use_docker_domain(self) -> None:
        for source in ("docker_read_only_snapshot", "docker_inspect_read_only"):
            self.assertTrue(incident_resolution_safe([source], [{"name": "docker", "state": "complete"}], global_resolution_safe=False))
            self.assertFalse(incident_resolution_safe([source], [{"name": "docker", "state": "disabled"}], global_resolution_safe=True))

    def test_unknown_source_remains_fail_closed_when_global_coverage_is_incomplete(self) -> None:
        self.assertFalse(incident_resolution_safe(["future_unknown_source"], [{"name": "processes", "state": "complete"}], global_resolution_safe=False))
        self.assertTrue(incident_resolution_safe(["future_unknown_source"], [{"name": "processes", "state": "complete"}], global_resolution_safe=True))


if __name__ == "__main__": unittest.main()
