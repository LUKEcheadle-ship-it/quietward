from __future__ import annotations

import json
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from quietward.collectors.command import CommandResult
from quietward.collectors.debian import DebianCollectorConfig, DebianReadOnlyCollector
from quietward.privacy_identity import PrivacyIdentity
from quietward.collectors.privacy import derive_host_id, stable_hash


class PrivacyIdentityTests(unittest.TestCase):
    def key(self, root: Path, value: bytes = b"a" * 32) -> Path:
        path = root / "privacy.key"
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    def test_keyed_identity_is_stable_and_installation_specific(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            one = PrivacyIdentity.load(self.key(root, b"a" * 32))
            two_path = self.key(root, b"b" * 32)
            two = PrivacyIdentity.load(two_path)
            self.assertEqual(one.identify("root"), one.identify("root"))
            self.assertNotEqual(one.identify("root"), two.identify("root"))
            self.assertNotEqual(one.identify("root"), "sha256-placeholder")
            self.assertEqual(len(one.identify("root")), 32)
            self.assertTrue(PrivacyIdentity.DOMAIN.startswith(b"quietward-"))

    def test_pre_rename_namespace_preserves_legacy_pseudonyms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.key(Path(directory), b"l" * 32)
            current = PrivacyIdentity.load(path)
            legacy = PrivacyIdentity.load(path, namespace="forge-sentinel-v1")
            self.assertNotEqual(current.identify("synthetic"), legacy.identify("synthetic"))
            self.assertEqual(
                legacy.identify("synthetic"),
                PrivacyIdentity.load(
                    path,
                    namespace="forge-sentinel-v1",
                ).identify("synthetic"),
            )

    def test_unknown_namespace_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "namespace"):
                PrivacyIdentity.load(
                    self.key(Path(directory)),
                    namespace="untrusted",
                )

    def test_pre_rename_collector_hash_namespace_preserves_host_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            machine_id = Path(directory) / "machine-id"
            machine_id.write_text("synthetic-machine\n", encoding="utf-8")
            expected = hashlib.sha256(
                b"forge-sentinel-v1\0synthetic-machine"
            ).hexdigest()[:16]
            self.assertEqual(
                derive_host_id(
                    machine_id,
                    namespace="forge-sentinel-v1",
                ),
                "host-" + expected,
            )
            self.assertNotEqual(
                stable_hash("synthetic", namespace="forge-sentinel-v1"),
                stable_hash("synthetic"),
            )
            with self.assertRaisesRegex(ValueError, "namespace"):
                stable_hash("synthetic", namespace="untrusted")

    def test_invalid_key_forms_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.key(root, b"x" * 31)
            with self.assertRaises(ValueError):
                PrivacyIdentity.load(path)
            path = self.key(root)
            if os.name != "nt":
                path.chmod(0o644)
                with self.assertRaises(ValueError):
                    PrivacyIdentity.load(path)
            target = self.key(root)
            link = root / "link"
            try:
                link.symlink_to(target)
            except OSError:
                return
            with self.assertRaises(ValueError):
                PrivacyIdentity.load(link)

    def test_auth_events_contain_only_keyed_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = self.key(Path(directory))
            journal = json.dumps({"MESSAGE": "Failed password for root from 192.0.2.44 port 22 ssh2"})
            runner = type("Runner", (), {"run": lambda self, argv: CommandResult(tuple(argv), 0, journal, "")})()
            collector = DebianReadOnlyCollector(
                DebianCollectorConfig(
                    sensitive_files=(),
                    include_processes=False,
                    include_sockets=False,
                    include_connections=False,
                    include_auth_journal=True,
                    include_docker=False,
                    include_persistence=False,
                    privacy_identity_key_path=key,
                ),
                runner=runner,
                host_id="synthetic-host",
            )
            batch = collector.collect()
            serialized = json.dumps(batch.to_dict(), sort_keys=True)
            self.assertNotIn("root", serialized)
            self.assertNotIn("192.0.2.44", serialized)
            self.assertIn("user_identity_hash", serialized)
            self.assertIn("raw_username_persisted", serialized)

    def test_missing_key_does_not_persist_auth_events(self) -> None:
        journal = json.dumps({"MESSAGE": "Failed password for admin from 192.0.2.44 port 22 ssh2"})
        runner = type("Runner", (), {"run": lambda self, argv: CommandResult(tuple(argv), 0, journal, "")})()
        collector = DebianReadOnlyCollector(
            DebianCollectorConfig(
                sensitive_files=(),
                include_processes=False,
                include_sockets=False,
                include_connections=False,
                include_auth_journal=True,
                include_docker=False,
                include_persistence=False,
                privacy_identity_key_path=Path("/tmp/does-not-exist-for-quietward"),
            ),
            runner=runner,
            host_id="synthetic-host",
        )
        batch = collector.collect()
        self.assertFalse(batch.events)
        self.assertTrue(any("privacy identity" in error for error in batch.snapshot.errors))

    def test_process_account_identity_is_keyed_in_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = self.key(Path(directory))
            runner = type("Runner", (), {"run": lambda self, argv: CommandResult(tuple(argv), 0, "1 0 root init /sbin/init\n2 1 operator python /usr/bin/python\n", "")})()
            collector = DebianReadOnlyCollector(
                DebianCollectorConfig(
                    sensitive_files=(),
                    include_processes=True,
                    include_sockets=False,
                    include_connections=False,
                    include_auth_journal=False,
                    include_docker=False,
                    include_persistence=False,
                    privacy_identity_key_path=key,
                ),
                runner=runner,
                host_id="synthetic-host",
            )
            serialized = json.dumps(collector.collect().snapshot.to_dict(), sort_keys=True)
            self.assertNotIn("root", serialized)
            self.assertNotIn("operator", serialized)
            self.assertIn("user_identity_hash", serialized)


if __name__ == "__main__":
    unittest.main()
