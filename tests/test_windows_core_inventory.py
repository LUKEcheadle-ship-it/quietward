from __future__ import annotations
import json, unittest
from quietward.collectors.windows_core import parse_windows_core_inventory
from quietward.privacy_identity import PrivacyIdentity
class WindowsCoreInventoryTests(unittest.TestCase):
    def setUp(self) -> None: self.identity = PrivacyIdentity(b"x" * 32)
    def payload(self, **overrides):
        value = {"DefenderOk": True, "Defender": {"AntivirusEnabled": True, "RealTimeProtectionEnabled": True, "AntivirusSignatureVersion": "1.2.3", "AntivirusSignatureAge": 1, "ActiveThreatCount": 0, "RemediationRequired": False}, "ProcessesOk": True, "Processes": [{"ProcessId": 4321, "ParentProcessId": 100, "Name": "example.exe", "ExecutablePath": "C:\\Program Files\\Example\\example.exe", "CommandLine": "example.exe --serve", "UserName": "TEST\\user"}], "SocketsOk": True, "Sockets": [{"Protocol": "tcp", "LocalAddress": "0.0.0.0", "LocalPort": 9443, "OwningProcess": 4321, "ProcessName": "example"}], "PersistenceOk": True, "Persistence": [{"Category": "scheduled_task", "Name": "\\Example", "Command": "C:\\Program Files\\Example\\example.exe --startup", "State": "Ready", "Account": "TEST\\user"}]}; value.update(overrides); return json.dumps(value)
    def test_parses_all_core_domains_and_listener_attribution(self) -> None:
        result = parse_windows_core_inventory(self.payload(), self.identity); self.assertTrue(result.complete); self.assertTrue(result.defender.antivirus_enabled); self.assertEqual(len(result.processes), 1); self.assertEqual(len(result.sockets), 1); self.assertEqual(len(result.persistence), 1); attribution = next(iter(result.listener_attribution.values())); self.assertEqual(attribution.owning_pid, 4321); self.assertEqual(attribution.executable, "example.exe"); self.assertEqual(attribution.confidence, "pid_inventory_match")
    def test_failed_domain_is_not_parsed_as_complete(self) -> None:
        result = parse_windows_core_inventory(self.payload(ProcessesOk=False, Processes=[{"ProcessId": 9999}]), self.identity); self.assertFalse(result.complete); self.assertFalse(result.processes_ok); self.assertEqual(result.processes, ()); self.assertTrue(result.sockets_ok)
    def test_persistence_requires_privacy_identity_before_storage(self) -> None:
        result = parse_windows_core_inventory(self.payload(), None); self.assertTrue(result.persistence_ok); self.assertEqual(result.persistence, ()); self.assertEqual(len(result.processes), 1)
if __name__ == "__main__": unittest.main()
