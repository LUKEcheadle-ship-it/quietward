from __future__ import annotations
import os, tempfile, unittest
from datetime import datetime, timezone
from pathlib import Path
from quietward.integrity import SelfIntegrityMonitor
class IntegrityPerformanceTests(unittest.TestCase):
    def test_unchanged_file_reuses_hash_between_full_audits_where_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"module.py"; path.write_text("alpha\n",encoding="utf-8"); clock=[0.0]; monitor=SelfIntegrityMonitor("host",[path],full_hash_interval_seconds=300.0,monotonic=lambda:clock[0]); first=monitor.scan(observed_at=datetime.now(timezone.utc)); self.assertTrue(first.full_hash_audit); self.assertEqual(first.files_hashed,1); clock[0]=10.0; second=monitor.scan(first.manifest,observed_at=datetime.now(timezone.utc)); self.assertFalse(second.full_hash_audit)
            if os.name=="nt": self.assertEqual(second.files_hashed,1); self.assertEqual(second.hashes_reused,0)
            else: self.assertEqual(second.files_hashed,0); self.assertEqual(second.hashes_reused,1)
            self.assertEqual(second.events,())
    def test_metadata_change_forces_immediate_rehash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"module.py"; path.write_text("alpha\n",encoding="utf-8"); clock=[0.0]; monitor=SelfIntegrityMonitor("host",[path],full_hash_interval_seconds=300.0,monotonic=lambda:clock[0]); first=monitor.scan(); clock[0]=10.0; path.write_text("bravo\n",encoding="utf-8"); second=monitor.scan(first.manifest); self.assertEqual(second.files_hashed,1); self.assertEqual(second.hashes_reused,0); self.assertEqual(len(second.events),1)
    def test_metadata_preserving_tamper_is_caught_without_waiting_for_full_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"module.py"; path.write_bytes(b"AAAAAA"); original=path.stat(); clock=[0.0]; monitor=SelfIntegrityMonitor("host",[path],full_hash_interval_seconds=300.0,monotonic=lambda:clock[0]); first=monitor.scan(); path.write_bytes(b"BBBBBB"); os.utime(path,ns=(original.st_atime_ns,original.st_mtime_ns)); clock[0]=10.0; fast=monitor.scan(first.manifest); self.assertEqual(fast.files_hashed,1); self.assertEqual(fast.hashes_reused,0); self.assertEqual(len(fast.events),1); clock[0]=301.0; audited=monitor.scan(fast.manifest); self.assertTrue(audited.full_hash_audit); self.assertEqual(audited.files_hashed,1); self.assertEqual(audited.events,())
    def test_timestamp_only_change_does_not_create_false_integrity_event(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"module.py"; path.write_text("same\n",encoding="utf-8"); clock=[0.0]; monitor=SelfIntegrityMonitor("host",[path],full_hash_interval_seconds=300.0,monotonic=lambda:clock[0]); first=monitor.scan(); original=path.stat(); clock[0]=10.0; os.utime(path,ns=(original.st_atime_ns,original.st_mtime_ns+1_000_000_000)); second=monitor.scan(first.manifest); self.assertEqual(second.files_hashed,1); self.assertEqual(second.events,())
if __name__=="__main__": unittest.main()
