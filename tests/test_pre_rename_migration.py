from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import StorageSettings, load_config
from quietward.contracts import EventKind, SecurityEvent
from quietward.pipeline import SentinelPipeline
from quietward.storage import SentinelStore
from scripts.migrate_pre_rename_user_install import (
    Layout,
    _migrated_config,
    finalize_migration,
    prepare_migration,
    rollback_prepared,
)


NOW = datetime(2026, 8, 17, tzinfo=timezone.utc)


class PreRenameMigrationTests(unittest.TestCase):
    def _private(self, path: Path, value: bytes) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    def _legacy(self, home: Path) -> Layout:
        layout = Layout(home)
        (layout.legacy_share / "app/forge_sentinel").mkdir(parents=True)
        (layout.legacy_share / "app/forge_sentinel/__init__.py").write_text(
            '__version__ = "0.3.0"\n', encoding="utf-8"
        )
        layout.legacy_config.mkdir(parents=True)
        layout.legacy_state.mkdir(parents=True)
        layout.legacy_unit.parent.mkdir(parents=True)
        layout.legacy_unit.write_text(
            "[Service]\nExecStart=forge-sentinel run\n", encoding="utf-8"
        )
        privacy = self._private(
            layout.legacy_config / "privacy-identity.key", b"p" * 32
        )
        evidence = self._private(
            layout.legacy_state / "evidence-signing.key", b"e" * 32
        )
        config = {
            "mode": "observe_only",
            "state_dir": str(layout.legacy_state),
            "collector": {
                "type": "debian_read_only_v3",
                "privacy_identity_key_path": str(privacy),
            },
            "storage": {
                "database_path": str(layout.legacy_state / "sentinel.sqlite3"),
                "alert_log_path": str(layout.legacy_state / "alerts.jsonl"),
                "evidence_signing_key_path": str(evidence),
            },
            "dashboard": {"bind": "127.0.0.1", "port": 8765},
            "actions": {"execute": False, "require_human_approval": True},
            "network": {"cloud_upload": False, "public_listener": False},
        }
        config_path = layout.legacy_config / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        config_path.chmod(0o600)
        settings = StorageSettings(
            database_path=layout.legacy_state / "sentinel.sqlite3",
            alert_log_path=layout.legacy_state / "alerts.jsonl",
            evidence_signing_key_path=evidence,
            evidence_signing_key_namespace="forge-sentinel-v1",
        )
        event = SecurityEvent(
            "legacy-event",
            NOW,
            "host-test",
            "test",
            EventKind.PERSISTENCE_CHANGE,
            "service:synthetic",
            {"persistence_indicator": True},
        )
        report = SentinelPipeline().analyze([event])
        with SentinelStore(settings) as store:
            store.persist_cycle(
                CollectionBatch(CollectorSnapshot(NOW, "host-test"), (event,)),
                report,
                started_at=NOW,
                completed_at=NOW,
            )
            store.set_finding_state(
                report.findings[0].finding_id,
                "expected",
                note="synthetic approved service",
            )
        (layout.legacy_state / "alerts.jsonl").write_text("", encoding="utf-8")
        (layout.legacy_state / "alerts.jsonl").chmod(0o600)
        return layout

    def test_prepare_preserves_identity_evidence_and_review_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._legacy(Path(directory))
            privacy_hash = (layout.legacy_config / "privacy-identity.key").read_bytes()
            evidence_hash = (layout.legacy_state / "evidence-signing.key").read_bytes()
            result = prepare_migration(layout, require_inactive=False)
            self.assertTrue(Path(str(result["backup"])).is_dir())
            self.assertEqual(
                privacy_hash,
                (layout.quietward_config / "privacy-identity.key").read_bytes(),
            )
            self.assertEqual(
                evidence_hash,
                (layout.quietward_state / "evidence-signing.key").read_bytes(),
            )
            config = load_config(layout.quietward_config / "config.json")
            self.assertEqual(config.collector.privacy_identity_namespace, "forge-sentinel-v1")
            self.assertEqual(config.collector.data_identity_namespace, "forge-sentinel-v1")
            self.assertEqual(config.storage.evidence_signing_key_namespace, "forge-sentinel-v1")
            with SentinelStore(config.storage) as store:
                self.assertTrue(store.verify_evidence_chain()["valid"])
                self.assertEqual(store.summary()["finding_states"]["expected"], 1)
            with self.assertRaisesRegex(ValueError, "already exists"):
                prepare_migration(layout, require_inactive=False)

    def test_legacy_packaged_scanner_paths_are_renamed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._legacy(Path(directory))
            path = layout.legacy_config / "config.json"
            config = json.loads(path.read_text(encoding="utf-8"))
            config["scanners"] = [
                {
                    "scanner": "yara",
                    "rules_path": "/var/lib/forge-sentinel/yara/sentinel.yar",
                },
                {
                    "scanner": "debsecan",
                    "data_source": "/var/lib/forge-sentinel/debsecan/vulnerability-data.json",
                },
            ]
            path.write_text(json.dumps(config), encoding="utf-8")
            path.chmod(0o600)
            migrated = _migrated_config(layout)
            self.assertEqual(
                migrated["scanners"][0]["rules_path"],
                "/var/lib/quietward/yara/quietward.yar",
            )
            self.assertEqual(
                migrated["scanners"][1]["data_source"],
                "/var/lib/quietward/debsecan/vulnerability-data.json",
            )

    def test_prepare_rejects_symlinked_legacy_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._legacy(Path(directory))
            target = layout.legacy_share / "target"
            target.write_text("safe", encoding="utf-8")
            link = layout.legacy_share / "link"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlink privilege unavailable")
            with self.assertRaisesRegex(ValueError, "symlink"):
                prepare_migration(layout, require_inactive=False)

    def test_rollback_moves_partial_quietward_install_into_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._legacy(Path(directory))
            prepare_migration(layout, require_inactive=False)
            layout.quietward_share.mkdir(parents=True)
            layout.quietward_unit.write_text("[Service]\n", encoding="utf-8")
            rollback_prepared(layout)
            self.assertFalse(layout.quietward_share.exists())
            self.assertFalse(layout.quietward_config.exists())
            self.assertFalse(layout.quietward_state.exists())
            self.assertFalse(layout.quietward_unit.exists())

    def test_finalize_disables_and_retires_legacy_install(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._legacy(Path(directory))
            result = prepare_migration(layout, require_inactive=False)
            calls: list[tuple[str, ...]] = []

            def fake_systemctl(args):
                values = tuple(args)
                calls.append(values)
                if values[:2] in {
                    ("is-active", "--quiet"),
                    ("is-enabled", "--quiet"),
                }:
                    returncode = 0 if values[-1] == "quietward.service" else 1
                else:
                    returncode = 0
                return subprocess.CompletedProcess(values, returncode, "", "")

            backup = finalize_migration(layout, systemctl=fake_systemctl)
            self.assertEqual(backup, Path(str(result["backup"])))
            self.assertIn(("disable", "forge-sentinel.service"), calls)
            self.assertFalse(layout.legacy_unit.exists())
            self.assertFalse(layout.legacy_share.exists())
            self.assertTrue((backup / "retired-originals/state/sentinel.sqlite3").is_file())


if __name__ == "__main__":
    unittest.main()
