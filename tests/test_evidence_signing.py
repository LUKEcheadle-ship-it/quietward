from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import QuietWardConfig, StorageSettings
from quietward.contracts import EventKind, SecurityEvent
from quietward.doctor import _evidence_signing_checks
from quietward.evidence import EvidenceSigner
from quietward.pipeline import SentinelPipeline
from quietward.storage import SentinelStore


class EvidenceSigningTests(unittest.TestCase):
    def _key(self, root: Path, value: bytes = b"k" * 32) -> Path:
        path = root / "evidence-signing.key"
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    def _settings(self, root: Path, **values: object) -> StorageSettings:
        return StorageSettings(
            database_path=root / "quietward.sqlite3",
            alert_log_path=root / "alerts.jsonl",
            **values,
        )

    def _cycle(self, index: int) -> tuple[CollectionBatch, object, datetime]:
        observed = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(
            seconds=index
        )
        event = SecurityEvent(
            event_id=f"event-{index}",
            observed_at=observed,
            host_id="host-test",
            source="test",
            kind=EventKind.FILE_CHANGE,
            subject=f"subject-{index}",
        )
        batch = CollectionBatch(
            CollectorSnapshot(observed_at=observed, host_id="host-test"),
            (event,),
        )
        return batch, SentinelPipeline().analyze([event]), observed

    def test_key_permissions_are_private(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX mode bits do not model Windows ACLs")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "key"
            path.write_bytes(b"x" * 32)
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "group/world"):
                EvidenceSigner.load(path)

    def test_symlinked_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = self._key(root)
            link = root / "linked-key"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlink privilege unavailable")
            with self.assertRaises(ValueError):
                EvidenceSigner.load(link)

    def test_key_identifier_uses_quietward_domain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            signer = EvidenceSigner.load(self._key(Path(temporary)))
            self.assertEqual(len(signer.key_id), 20)
            self.assertEqual(signer.algorithm, "hmac-sha256-v1")

    def test_pre_rename_namespace_preserves_legacy_signatures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._key(Path(temporary))
            current = EvidenceSigner.load(path)
            legacy = EvidenceSigner.load(
                path,
                key_id_namespace="forge-sentinel-v1",
            )
            self.assertNotEqual(current.key_id, legacy.key_id)
            signature = legacy.sign(7, "a" * 64)
            self.assertTrue(legacy.verify(7, "a" * 64, signature))
            self.assertFalse(current.verify(7, "a" * 64, signature))

    def test_unknown_key_namespace_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "namespace"):
                EvidenceSigner.load(
                    self._key(Path(temporary)),
                    key_id_namespace="untrusted",
                )

    def test_key_with_windows_text_eof_byte_loads_completely(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            key = b"a" * 16 + b"\x1a" + b"b" * 47
            signer = EvidenceSigner.load(self._key(Path(temporary), key))
            self.assertEqual(signer.key, key)

    def test_signed_cycle_detects_signature_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = self._settings(root, evidence_signing_key_path=self._key(root))
            with SentinelStore(settings) as store:
                batch, report, observed = self._cycle(1)
                persisted = store.persist_cycle(batch, report, started_at=observed, completed_at=observed)
                self.assertIsNotNone(persisted.signature)
                self.assertTrue(store.verify_evidence_chain()["valid"])
                store.connection.execute("UPDATE evidence_signatures SET signature='0' WHERE cycle_id=?", (persisted.cycle_id,))
                store.connection.commit()
                result = store.verify_evidence_chain()
                self.assertFalse(result["valid"])
                self.assertTrue(any("signature mismatch" in item for item in result["errors"]))

    def test_enabling_signing_preserves_legacy_unsigned_cycles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with SentinelStore(self._settings(root)) as store:
                batch, report, observed = self._cycle(1)
                store.persist_cycle(batch, report, started_at=observed, completed_at=observed)
            signed_settings = self._settings(root, evidence_signing_key_path=self._key(root))
            with SentinelStore(signed_settings) as store:
                batch, report, observed = self._cycle(2)
                store.persist_cycle(batch, report, started_at=observed, completed_at=observed)
                result = store.verify_evidence_chain()
                self.assertTrue(result["valid"], result)
                self.assertEqual(result["signature_required_from_cycle"], 2)
                self.assertEqual(result["signatures_checked"], 1)

    def test_missing_or_changed_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = self._key(root, b"a" * 32)
            signed_settings = self._settings(root, evidence_signing_key_path=key)
            with SentinelStore(signed_settings) as store:
                batch, report, observed = self._cycle(1)
                store.persist_cycle(batch, report, started_at=observed, completed_at=observed)
            with SentinelStore(self._settings(root)) as store:
                self.assertFalse(store.verify_evidence_chain()["valid"])
                batch, report, observed = self._cycle(2)
                with self.assertRaisesRegex(ValueError, "signing key"):
                    store.persist_cycle(batch, report, started_at=observed, completed_at=observed)
            key.write_bytes(b"b" * 32)
            key.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "does not match"):
                SentinelStore(signed_settings)

    def test_cycle_retention_preserves_a_verifiable_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = self._settings(root, max_cycles=2, evidence_signing_key_path=self._key(root))
            with SentinelStore(settings) as store:
                for index in range(1, 5):
                    batch, report, observed = self._cycle(index)
                    store.persist_cycle(batch, report, started_at=observed, completed_at=observed)
                summary = store.summary()
                self.assertEqual(summary["cycles"], 2)
                self.assertEqual(summary["evidence_signatures"], 2)
                result = store.verify_evidence_chain()
                self.assertTrue(result["valid"], result)
                self.assertEqual(result["anchor_cycle"], 2)
                self.assertEqual(result["cycles_checked"], 2)

    def test_scanner_run_history_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = self._settings(root, max_scanner_runs=2)
            with SentinelStore(settings) as store:
                for index in range(3):
                    observed = (datetime.now(timezone.utc) + timedelta(seconds=index)).isoformat().replace("+00:00", "Z")
                    store.record_scanner_run({"scanner": "test", "started_at": observed, "completed_at": observed, "status": "ok", "events_count": 0, "actions_executed": 0})
                batch, report, observed = self._cycle(1)
                store.persist_cycle(batch, report, started_at=observed, completed_at=observed)
                self.assertEqual(store.summary()["scanner_runs"], 2)

    def test_config_and_doctor_validate_signing_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = self._key(root)
            config = QuietWardConfig.from_dict({"state_dir": str(root), "storage": {"evidence_signing_key_path": str(key), "max_cycles": 50, "max_scanner_runs": 100}})
            self.assertEqual(config.storage.max_cycles, 50)
            self.assertEqual(config.storage.max_scanner_runs, 100)
            self.assertEqual(_evidence_signing_checks(config)[0].status, "PASS")


if __name__ == "__main__":
    unittest.main()
