from __future__ import annotations
import json, sqlite3, unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from quietward.source_aware_lifecycle import SourceAwareIncidentLifecycleRepository
class LifecycleScalingTests(unittest.TestCase):
    def test_live_reconciliation_does_not_materialize_large_resolved_history(self) -> None:
        connection=sqlite3.connect(":memory:"); self.addCleanup(connection.close); repository=SourceAwareIncidentLifecycleRepository(connection); now=datetime(2026,8,8,8,0,tzinfo=timezone.utc); timestamp=now.isoformat().replace("+00:00","Z")
        resolved_rows=[]
        for index in range(5000): resolved_rows.append((f"resolved-{index:05d}",f"sig-{index:05d}",f"finding-{index:05d}","host-a",f"subject-{index:05d}","low",20,json.dumps(["new_listening_port"]),json.dumps(["windows_socket_snapshot"]),"resolved",timestamp,timestamp,timestamp,2,1,0,1))
        active=("active-one","sig-active","finding-active","host-a","tcp://*:4444","high",70,json.dumps(["new_listening_port"]),json.dumps(["windows_socket_snapshot"]),"recurring",timestamp,timestamp,None,2,2,1,1)
        with connection:
            connection.executemany("INSERT INTO incident_lifecycle(incident_key,signature,finding_id,host_id,subject,severity,score_band,event_kinds_json,event_sources_json,state,first_seen,last_seen,resolved_at,cycles_seen,occurrences,active,last_cycle_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",resolved_rows); connection.execute("INSERT INTO incident_lifecycle(incident_key,signature,finding_id,host_id,subject,severity,score_band,event_kinds_json,event_sources_json,state,first_seen,last_seen,resolved_at,cycles_seen,occurrences,active,last_cycle_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",active); repository._set_meta("last_processed_cycle_id","1")
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM incident_lifecycle").fetchone()[0],5001); self.assertEqual(set(repository._load_relevant_records(())),{"active-one"})
        with mock.patch.object(repository,"load_records",side_effect=AssertionError("live path must not load all incident history")):
            result=repository.reconcile_cycle(2,[],[],observed_at=now+timedelta(minutes=1),coverage_complete=True,coverage_domains=[{"name":"listening_sockets","state":"complete"}])
        self.assertEqual(result.resolved,1); self.assertEqual(result.active_total,0); self.assertEqual(connection.execute("SELECT COUNT(*) FROM incident_lifecycle WHERE active=1").fetchone()[0],0); self.assertEqual(connection.execute("SELECT COUNT(*) FROM incident_lifecycle").fetchone()[0],5001)
if __name__=="__main__": unittest.main()
