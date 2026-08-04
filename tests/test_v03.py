from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quietward.alerts import LocalAlertSink
from quietward.collectors.command import DOCKER_INSPECT_PREFIX, ReadOnlyCommandRunner
from quietward.collectors.diff import diff_snapshots
from quietward.collectors.models import CollectionBatch, CollectorSnapshot, ContainerRecord, PersistenceRecord
from quietward.collectors.parsers import parse_docker_inspect_output
from quietward.collectors.persistence import observe_persistence
from quietward.config import QuietWardConfig, StorageSettings, load_config
from quietward.contracts import EventKind, SecurityEvent
from quietward.integrity import SelfIntegrityMonitor
from quietward.pipeline import SentinelPipeline
from quietward.service import QuietWardService
from quietward.storage import SentinelStore

NOW = datetime(2026, 7, 30, 19, 0, tzinfo=timezone.utc)


class V03Tests(unittest.TestCase):
    def test_snapshot_positional_contract_remains_backward_compatible(self) -> None:
        snapshot = CollectorSnapshot(NOW, "host-a", (), (), (), (), ("optional warning",), "debian-read-only-v1")
        self.assertEqual(snapshot.errors, ("optional warning",))
        self.assertEqual(snapshot.persistence, ())

    def test_docker_inspect_dynamic_allowlist_is_bounded(self) -> None:
        good = (*DOCKER_INSPECT_PREFIX, "a" * 64)
        self.assertEqual(ReadOnlyCommandRunner.validate(good), good)
        with self.assertRaises(ValueError):
            ReadOnlyCommandRunner.validate((*DOCKER_INSPECT_PREFIX, "../../etc/passwd"))
        with self.assertRaises(ValueError):
            ReadOnlyCommandRunner.validate(("docker", "exec", "a" * 64, "sh"))

    def test_docker_inspect_extracts_high_risk_configuration(self) -> None:
        base = ContainerRecord("hash", "image:latest", "svc", "Up")
        report = {
            "HostConfig": {"Privileged": True, "NetworkMode": "host", "PidMode": "host", "IpcMode": "", "ReadonlyRootfs": False, "SecurityOpt": [], "CapAdd": ["SYS_ADMIN"]},
            "Mounts": [{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}],
            "RestartCount": 7,
            "State": {"Health": {"Status": "unhealthy"}},
            "Config": {"Image": "image:latest"},
        }
        record = parse_docker_inspect_output(json.dumps(report), base)
        self.assertTrue(record.privileged)
        self.assertIn("docker_socket_mount", record.security_markers)
        self.assertIn("sensitive_capability", record.security_markers)
        self.assertIn("restart_loop", record.security_markers)
        self.assertIsNotNone(record.security_fingerprint)

    def test_persistence_inventory_hashes_accounts_and_authorized_keys(self) -> None:
        if os.name == "nt":
            self.skipTest("Linux persistence inventory")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            passwd = root / "passwd"
            group = root / "group"
            home = root / "home" / "alice"
            authorized = home / ".ssh" / "authorized_keys"
            authorized.parent.mkdir(parents=True)
            passwd.write_text(f"root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::{home}:/bin/bash\n", encoding="utf-8")
            group.write_text("sudo:x:27:alice\n", encoding="utf-8")
            authorized.write_text("ssh-ed25519 AAAATEST alice@example\n", encoding="utf-8")
            records, errors = observe_persistence(passwd_path=passwd, group_path=group, globs=(), max_entries=50)
            self.assertEqual(errors, ())
            self.assertIn("user:alice", {item.subject for item in records})
            self.assertIn("group:sudo", {item.subject for item in records})
            key = next(item for item in records if item.category == "authorized_keys")
            self.assertEqual(key.metadata["key_count"], 1)
            self.assertNotIn("AAAATEST", json.dumps(key.to_dict()))

    def test_snapshot_diff_emits_account_persistence_and_container_config_events(self) -> None:
        before = CollectorSnapshot(NOW, "host-a", containers=(ContainerRecord("id", "img", "svc", "Up", security_fingerprint="old"),), persistence=(PersistenceRecord("account", "user:alice", "old"),))
        after = CollectorSnapshot(NOW + timedelta(minutes=1), "host-a", containers=(ContainerRecord("id", "img", "svc", "Up", privileged=True, security_markers=("privileged_container",), security_fingerprint="new"),), persistence=(PersistenceRecord("account", "user:alice", "new", ("interactive_shell",)), PersistenceRecord("cron", "/etc/cron.d/x", "abc", ("scheduled_persistence",))))
        kinds = {event.kind for event in diff_snapshots(after, before)}
        self.assertIn(EventKind.ACCOUNT_CHANGE, kinds)
        self.assertIn(EventKind.PERSISTENCE_CHANGE, kinds)
        self.assertIn(EventKind.CONTAINER_CONFIGURATION_CHANGE, kinds)

    def test_integrity_monitor_baselines_then_detects_change_without_raw_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "config.json"
            target.write_text('{"mode":"observe_only"}', encoding="utf-8")
            monitor = SelfIntegrityMonitor("host-a", [target])
            baseline = monitor.scan(observed_at=NOW)
            self.assertEqual(baseline.events, ())
            target.write_text('{"mode":"observe_only","changed":true}', encoding="utf-8")
            changed = monitor.scan(baseline.manifest, observed_at=NOW + timedelta(minutes=1))
            self.assertEqual(len(changed.events), 1)
            self.assertEqual(changed.events[0].kind, EventKind.SELF_INTEGRITY_CHANGE)
            self.assertEqual(changed.events[0].source, "quietward_self_integrity")
            self.assertNotIn('"changed":true', json.dumps(changed.events[0].to_dict()))

    def test_storage_chain_reviews_and_suppressions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            settings = StorageSettings(root / "quietward.sqlite3", root / "alerts.jsonl", max_snapshots=10, max_events=100, max_findings=100, retention_days=30)
            event = SecurityEvent("event-1", NOW, "host-a", "test", EventKind.PERSISTENCE_CHANGE, "/etc/cron.d/x", {"persistence_indicator": True})
            batch = CollectionBatch(CollectorSnapshot(NOW, "host-a"), (event,))
            report = SentinelPipeline().analyze([event])
            with SentinelStore(settings) as store:
                persisted = store.persist_cycle(batch, report, started_at=NOW, completed_at=NOW)
                self.assertTrue(persisted.chain_hash)
                self.assertTrue(store.verify_evidence_chain()["valid"])
                finding_id = report.findings[0].finding_id
                review = store.set_finding_state(finding_id, "suppressed", note="expected job", suppress_until=NOW + timedelta(hours=1), create_rule=True)
                self.assertEqual(review["state"], "suppressed")
                kept, suppressed = store.filter_suppressed_events([event], now=NOW)
                self.assertEqual(kept, [])
                self.assertEqual(len(suppressed), 1)
                malware = SecurityEvent("event-2", NOW, "host-a", "clamav", EventKind.MALWARE_SIGNATURE, "/tmp/x", {})
                kept, suppressed = store.filter_suppressed_events([malware], now=NOW)
                self.assertEqual(len(kept), 1)
                self.assertEqual(suppressed, [])

    def test_evidence_chain_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            settings = StorageSettings(root / "db.sqlite3", root / "alerts.jsonl")
            event = SecurityEvent("event-1", NOW, "host-a", "test", EventKind.ACCOUNT_CHANGE, "user:x", {})
            batch = CollectionBatch(CollectorSnapshot(NOW, "host-a"), (event,))
            report = SentinelPipeline().analyze([event])
            with SentinelStore(settings) as store:
                store.persist_cycle(batch, report, started_at=NOW, completed_at=NOW)
                store.connection.execute("UPDATE evidence_chain SET payload_json='{}' WHERE cycle_id=1")
                store.connection.commit()
                result = store.verify_evidence_chain()
                self.assertFalse(result["valid"])
                self.assertTrue(any("payload hash mismatch" in item for item in result["errors"]))

    def test_config_defaults_enable_persistence_and_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            config = QuietWardConfig.from_dict({"state_dir": str(state)})
            self.assertTrue(config.collector.include_persistence)
            self.assertTrue(config.self_integrity.enabled)
            with self.assertRaises(ValueError):
                QuietWardConfig.from_dict({"state_dir": str(state), "self_integrity": {"extra_paths": ["relative"]}})

    def test_service_integrates_suppression_integrity_and_chain(self) -> None:
        class Collector:
            host_id = "host-a"
            def __init__(self) -> None:
                self.index = 0
            def collect(self, previous=None):
                self.index += 1
                event = SecurityEvent(f"proc-{self.index}", NOW + timedelta(minutes=self.index), "host-a", "test", EventKind.PROCESS_START, "proc:expected", {"suspicious_markers": ["test"], "persistence_indicator": True})
                return CollectionBatch(CollectorSnapshot(NOW + timedelta(minutes=self.index), "host-a"), (event,))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_path = root / "config.json"
            config_path.write_text(json.dumps({"state_dir": str(root / "state"), "dashboard": {"enabled": False}}), encoding="utf-8")
            config = load_config(config_path)
            watched = root / "watched.py"
            watched.write_text("x=1\n", encoding="utf-8")
            collector = Collector()
            store = SentinelStore(config.storage)
            monitor = SelfIntegrityMonitor("host-a", [watched])
            service = QuietWardService(config, collector=collector, store=store, alert_sink=LocalAlertSink(config.storage.alert_log_path), integrity_monitor=monitor, clock=lambda: NOW + timedelta(minutes=collector.index))
            first = service.run_cycle()
            self.assertEqual(first.integrity_events, 0)
            finding_id = store.recent_findings()[0]["finding_id"]
            store.set_finding_state(finding_id, "expected", create_rule=True)
            watched.write_text("x=2\n", encoding="utf-8")
            second = service.run_cycle()
            self.assertEqual(second.suppressed_events, 1)
            self.assertEqual(second.integrity_events, 1)
            self.assertIn(EventKind.SELF_INTEGRITY_CHANGE.value, {item["kind"] for item in store.recent_events(20)})
            self.assertTrue(store.verify_evidence_chain()["valid"])
            service.close()
            store.close()

    def test_incident_commands_parse(self) -> None:
        from quietward.cli import build_parser
        args = build_parser().parse_args(["incident", "--config", "/tmp/config.json", "suppress", "finding-1", "--minutes", "30", "--note", "maintenance"])
        self.assertEqual(args.command, "incident")
        self.assertEqual(args.incident_action, "suppress")
        self.assertEqual(args.minutes, 30)


if __name__ == "__main__":
    unittest.main()
