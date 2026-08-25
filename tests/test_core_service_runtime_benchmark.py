from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.benchmark_core_service_runtime import (
    _initialize_temporary_privacy_key,
    _initialize_temporary_signing_key,
    _measurement_config,
)


class CoreServiceRuntimeBenchmarkTests(unittest.TestCase):
    def test_measurement_config_redirects_writable_state_and_disables_optional_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source_state = root / "source-state"
            source_state.mkdir()
            config_path = root / "source-config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "state_dir": str(source_state),
                        "collector": {
                            "interval_seconds": 60,
                            "include_processes": True,
                            "include_listening_sockets": True,
                            "include_auth_journal": False,
                            "include_docker": False,
                            "include_persistence": False,
                            "sensitive_files": [],
                            "privacy_identity_key_path": str(source_state / "source-privacy.key"),
                        },
                        "storage": {
                            "database_path": str(source_state / "source.sqlite3"),
                            "alert_log_path": str(source_state / "source-alerts.jsonl"),
                            "evidence_signing_key_path": str(source_state / "source-signing.key"),
                        },
                        "service": {
                            "health_path": str(source_state / "source-health.json"),
                            "lock_path": str(source_state / "source.lock"),
                        },
                        "dashboard": {"enabled": True},
                        "self_integrity": {"enabled": True},
                        "micro_llm": {"enabled": True, "model": "local-test"},
                        "scanners": [{
                            "scanner": "yara",
                            "enabled": True,
                            "interval_seconds": 3600,
                            "timeout_seconds": 30,
                            "targets": [str(root)],
                            "rules_path": str(root / "rules.yar"),
                        }],
                    }
                ),
                encoding="utf-8",
            )
            measurement_root = root / "measurement-state"
            config = _measurement_config(config_path, measurement_root)
            self.assertEqual(config.state_dir, measurement_root)
            self.assertEqual(config.collector.privacy_identity_key_path, measurement_root / "privacy-identity.key")
            self.assertEqual(config.storage.database_path, measurement_root / "measurement.sqlite3")
            self.assertEqual(config.storage.alert_log_path, measurement_root / "alerts.jsonl")
            self.assertEqual(config.storage.evidence_signing_key_path, measurement_root / "evidence-signing.key")
            self.assertEqual(config.service.health_path, measurement_root / "health.json")
            self.assertEqual(config.service.lock_path, measurement_root / "service.lock")
            self.assertFalse(config.dashboard.enabled)
            self.assertFalse(config.micro_llm.enabled)
            self.assertFalse(config.self_integrity.enabled)
            self.assertTrue(config.scanners)
            self.assertTrue(all(not job.enabled for job in config.scanners))
            self.assertEqual(config.collector.interval_seconds, 60.0)
            self.assertNotEqual(config.storage.database_path, source_state / "source.sqlite3")
            self.assertNotEqual(config.storage.evidence_signing_key_path, source_state / "source-signing.key")
            self.assertNotEqual(config.collector.privacy_identity_key_path, source_state / "source-privacy.key")

    def test_temporary_signing_key_is_created_privately_and_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "state" / "evidence-signing.key"
            _initialize_temporary_signing_key(path)
            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_size, 64)
            first = path.read_bytes()
            self.assertEqual(len(first), 64)
            with self.assertRaises(FileExistsError):
                _initialize_temporary_signing_key(path)
            self.assertEqual(path.read_bytes(), first)

    def test_temporary_privacy_key_is_created_privately_and_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "state" / "privacy-identity.key"
            _initialize_temporary_privacy_key(path)
            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_size, 64)
            first = path.read_bytes()
            with self.assertRaises(FileExistsError):
                _initialize_temporary_privacy_key(path)
            self.assertEqual(path.read_bytes(), first)

    def test_temporary_key_preserves_newline_bytes_exactly(self) -> None:
        payload = b"\n" + (b"x" * 31) + b"\n" + (b"y" * 31)
        self.assertEqual(len(payload), 64)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "state" / "privacy-identity.key"
            with mock.patch("scripts.benchmark_core_service_runtime.os.urandom", return_value=payload):
                _initialize_temporary_privacy_key(path)
            self.assertEqual(path.stat().st_size, 64)
            self.assertEqual(path.read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()
