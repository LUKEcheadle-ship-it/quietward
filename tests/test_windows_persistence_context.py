from __future__ import annotations
import json, unittest
from quietward.collectors.windows_commands import PERSISTENCE_SCRIPT
from quietward.collectors.windows_parsers import parse_windows_persistence
from quietward.privacy_identity import PrivacyIdentity
class WindowsPersistenceContextTests(unittest.TestCase):
    def setUp(self) -> None: self.identity = PrivacyIdentity(b"quietward-test-key-material-32-bytes!!")
    def test_scheduled_task_command_and_account_are_hashed_not_persisted(self) -> None:
        raw_name="\\Vendor\\Updater"; raw_command="C:\\Users\\alice\\AppData\\Local\\Vendor\\updater.exe --fetch https://updates.example.test/payload"; raw_account="MACHINE\\alice"; text=json.dumps({"Category":"scheduled_task","Name":raw_name,"Command":raw_command,"State":"Ready","Account":raw_account}); records=parse_windows_persistence(text,self.identity); self.assertEqual(len(records),1); record=records[0]; self.assertEqual(record.category,"scheduled_task"); self.assertIn("user_writable_target",record.risk_markers); self.assertIn("network_target",record.risk_markers); self.assertIsNotNone(record.metadata["command_hash"]); self.assertIsNotNone(record.metadata["account_identity_hash"]); self.assertFalse(record.metadata["raw_name_persisted"]); self.assertFalse(record.metadata["raw_command_persisted"]); self.assertFalse(record.metadata["raw_account_persisted"]); serialized=json.dumps(record.to_dict(),sort_keys=True); self.assertNotIn(raw_name,serialized); self.assertNotIn(raw_command,serialized); self.assertNotIn(raw_account,serialized); self.assertNotIn("alice",serialized.casefold())
    def test_service_context_keeps_privileged_marker_without_raw_account(self) -> None:
        raw_command='"C:\\Program Files\\Vendor\\agent.exe" --service'; text=json.dumps({"Category":"service_auto","Name":"VendorAgent","Command":raw_command,"State":"enabled","Account":"LocalSystem"}); record=parse_windows_persistence(text,self.identity)[0]; self.assertIn("privileged_service",record.risk_markers); serialized=json.dumps(record.to_dict(),sort_keys=True); self.assertNotIn("LocalSystem",serialized); self.assertNotIn(raw_command,serialized)
    def test_powershell_inventory_collects_task_actions_and_principal(self) -> None:
        self.assertIn("$task.Actions",PERSISTENCE_SCRIPT); self.assertIn("$task.Principal.UserId",PERSISTENCE_SCRIPT); self.assertIn("Command=($commands -join ' | ')",PERSISTENCE_SCRIPT)
if __name__ == "__main__": unittest.main()
