from __future__ import annotations
import json, unittest
from datetime import datetime, timezone
from quietward.collectors.models import ProcessRecord
from quietward.collectors.windows_attribution import build_listener_attribution, enrich_listener_events
from quietward.contracts import EventKind, SecurityEvent
class WindowsListenerAttributionTests(unittest.TestCase):
    def process(self) -> ProcessRecord: return ProcessRecord(pid=4242, ppid=4000, user="a"*32, command_name="example.exe", executable="example.exe", args_hash="b"*32, suspicious_markers=("user_writable_executable",), privileged_context=True)
    def socket_json(self, *, pid=4242, process_name="example") -> str: return json.dumps({"Protocol":"tcp","LocalAddress":"0.0.0.0","LocalPort":4444,"OwningProcess":pid,"ProcessName":process_name})
    def event(self) -> SecurityEvent: return SecurityEvent("qwe-listener", datetime(2026,8,7,21,0,tzinfo=timezone.utc), "host-a", "windows_socket_snapshot", EventKind.NEW_LISTENING_PORT, "tcp://*:4444", {"protocol":"tcp","local_address":"*","port":4444,"process_name":"example","external_bind":True,"privileged_context":False,"baseline_deviation":1.0}, 0.8)
    def test_pid_inventory_match_adds_process_context(self) -> None:
        attribution=build_listener_attribution(self.socket_json(),[self.process()]); self.assertEqual(len(attribution),1); record=next(iter(attribution.values())); self.assertEqual(record.owning_pid,4242); self.assertEqual(record.executable,"example.exe"); self.assertEqual(record.confidence,"pid_inventory_match"); self.assertTrue(record.privileged_context)
        enriched=enrich_listener_events([self.event()],attribution)[0]; self.assertEqual(enriched.attributes["owner_pid"],4242); self.assertEqual(enriched.attributes["owner_executable"],"example.exe"); self.assertEqual(enriched.attributes["owner_suspicious_markers"],["user_writable_executable"]); self.assertEqual(enriched.attributes["process_attribution"],"pid_inventory_match"); self.assertTrue(enriched.attributes["privileged_context"]); self.assertFalse(enriched.attributes["raw_command_line_persisted"]); self.assertFalse(enriched.attributes["raw_username_persisted"]); self.assertGreaterEqual(enriched.confidence,0.9)
    def test_unknown_pid_is_retained_without_inventing_executable(self) -> None:
        record=next(iter(build_listener_attribution(self.socket_json(pid=9999),[self.process()]).values())); self.assertEqual(record.owning_pid,9999); self.assertIsNone(record.executable); self.assertEqual(record.confidence,"socket_pid_only")
    def test_missing_pid_falls_back_to_process_name(self) -> None:
        record=next(iter(build_listener_attribution(self.socket_json(pid=None),[]).values())); self.assertIsNone(record.owning_pid); self.assertEqual(record.confidence,"process_name_only")
    def test_event_without_matching_attribution_is_explicit(self) -> None:
        enriched=enrich_listener_events([self.event()],{})[0]; self.assertEqual(enriched.attributes["process_attribution"],"unattributed"); self.assertNotIn("owner_executable",enriched.attributes)
    def test_non_listener_event_is_unchanged(self) -> None:
        event=SecurityEvent("qwe-file",datetime(2026,8,7,21,0,tzinfo=timezone.utc),"host-a","windows_file_integrity_snapshot",EventKind.SENSITIVE_FILE_CHANGE,"file",{"baseline_deviation":1.0}); self.assertIs(enrich_listener_events([event],{})[0],event)
    def test_local_addresses_are_reduced_to_scope(self) -> None:
        text=json.dumps([{"Protocol":"tcp","LocalAddress":"127.0.0.1","LocalPort":80,"OwningProcess":0,"ProcessName":"local"},{"Protocol":"tcp","LocalAddress":"192.168.1.10","LocalPort":81,"OwningProcess":0,"ProcessName":"private"}]); attribution=build_listener_attribution(text,[]); scopes={item.local_address for item in attribution.values()}; self.assertEqual(scopes,{"loopback","private-interface"}); self.assertNotIn("192.168.1.10",str(attribution))
if __name__ == "__main__": unittest.main()
