from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from quietward.cadence import CadenceLane
from quietward.cadenced_service import CadencedPerformanceSentinelService
from quietward.config import SentinelConfig
from quietward.core_service import CoreSentinelService
from quietward.core_store import CoreSentinelStore
from quietward.maintenance_governor import AdaptiveMaintenanceGovernor
from quietward.performance_service import PerformanceSentinelService
from quietward.performance_store import PerformanceSentinelStore
from quietward.runtime import build_service


class RuntimePerformanceStoreTests(unittest.TestCase):
    def test_build_service_uses_core_service_store_and_governor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = SentinelConfig.from_dict({
                "state_dir": str(Path(temporary).resolve()),
                "collector": {"include_auth_journal": False, "include_docker": False, "include_persistence": False, "sensitive_files": []},
                "dashboard": {"enabled": False},
                "self_integrity": {"enabled": False},
            })
            service = build_service(config)
            try:
                self.assertIsInstance(service, CoreSentinelService)
                self.assertIsInstance(service, CadencedPerformanceSentinelService)
                self.assertIsInstance(service, PerformanceSentinelService)
                self.assertIsInstance(service.store, CoreSentinelStore)
                self.assertIsInstance(service.store, PerformanceSentinelStore)
                self.assertIsInstance(service.adaptive_governor, AdaptiveMaintenanceGovernor)
                self.assertTrue(service.owns_store)
                self.assertEqual(service.store.full_audit_interval_seconds, 300.0)
                self.assertEqual(service.store.runtime_summary_cache_seconds, 300.0)
                self.assertEqual(service.cadence_controller.intervals[CadenceLane.STANDARD], 300.0)
                self.assertEqual(service.cadence_controller.intervals[CadenceLane.DEEP], 300.0)
                self.assertEqual(service.adaptive_governor.max_consecutive_deferrals, 2)
                self.assertEqual(service.store.runtime_summary()["actions_executed"], 0)
            finally:
                service.close()


if __name__ == "__main__":
    unittest.main()
