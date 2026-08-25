from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import StorageSettings
from quietward.contextual_pipeline import ContextualPipeline
from quietward.contracts import EventKind, SecurityEvent
from quietward.pipeline import SentinelPipeline
from quietward.product_store import ProductSentinelStore
from quietward.storage import SentinelStore


class ScopedExpectedRuleTests(unittest.TestCase):
    def test_expected_rule_only_suppresses_reviewed_event_kinds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); settings = StorageSettings(database_path=root / "quietward.sqlite3", alert_log_path=root / "alerts.jsonl"); now = datetime(2026, 8, 7, 22, 0, tzinfo=timezone.utc)
            events = [SecurityEvent("socket", now, "host", "test", EventKind.NEW_LISTENING_PORT, "shared-subject"), SecurityEvent("outbound", now, "host", "test", EventKind.OUTBOUND_CONNECTION, "shared-subject")]
            report = SentinelPipeline().analyze(events); self.assertEqual(len(report.findings), 1); finding_id = report.findings[0].finding_id
            with ProductSentinelStore(settings) as store:
                store.persist_cycle(CollectionBatch(CollectorSnapshot(now, "host"), tuple(events)), report, started_at=now, completed_at=now); store.set_finding_state(finding_id, "expected", note="reviewed", create_rule=True)
                row = store.connection.execute("SELECT kinds_json FROM suppression_rules WHERE source_finding_id=?", (finding_id,)).fetchone(); self.assertIsNotNone(row); kinds = set(json.loads(str(row[0]))); self.assertEqual(kinds, {EventKind.NEW_LISTENING_PORT.value, EventKind.OUTBOUND_CONNECTION.value})
                malware = SecurityEvent("malware", now, "host", "test", EventKind.MALWARE_SIGNATURE, "shared-subject"); kept, suppressed = store.filter_suppressed_events([*events, malware], now=now); self.assertEqual({item.event_id for item in suppressed}, {"socket", "outbound"}); self.assertEqual({item.event_id for item in kept}, {"malware"})

    def test_temporal_prior_evidence_does_not_broaden_current_expected_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); settings = StorageSettings(database_path=root / "quietward.sqlite3", alert_log_path=root / "alerts.jsonl"); first_time = datetime(2026, 8, 8, 14, 0, tzinfo=timezone.utc); second_time = first_time + timedelta(minutes=1)
            prior = SecurityEvent("prior-process", first_time, "host", "windows_process_snapshot", EventKind.PROCESS_START, "process:agent", {"pid": 4242, "process_name": "agent.exe"})
            current = SecurityEvent("current-listener", second_time, "host", "windows_socket_snapshot", EventKind.NEW_LISTENING_PORT, "tcp://0.0.0.0:4444", {"owner_pid": 4242, "owner_command_name": "agent.exe", "external_bind": True})
            pipeline = ContextualPipeline(SentinelPipeline())
            with ProductSentinelStore(settings) as store:
                first_report = pipeline.analyze([prior]); store.persist_cycle(CollectionBatch(CollectorSnapshot(first_time, "host"), (prior,)), first_report, started_at=first_time, completed_at=first_time); pipeline.commit_pending()
                second_report = pipeline.analyze([current]); self.assertEqual(len(second_report.findings), 1); finding = second_report.findings[0]; self.assertIn("prior-process", finding.evidence_event_ids); self.assertIn("current-listener", finding.evidence_event_ids)
                store.persist_cycle(CollectionBatch(CollectorSnapshot(second_time, "host"), (current,)), second_report, started_at=second_time, completed_at=second_time); pipeline.commit_pending(); store.set_finding_state(finding.finding_id, "expected", note="reviewed current listener only", create_rule=True)
                row = store.connection.execute("SELECT kinds_json FROM suppression_rules WHERE source_finding_id=?", (finding.finding_id,)).fetchone(); self.assertIsNotNone(row); kinds = set(json.loads(str(row[0]))); self.assertEqual(kinds, {EventKind.NEW_LISTENING_PORT.value}); self.assertNotIn(EventKind.PROCESS_START.value, kinds)

    def test_reopen_disables_scoped_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); settings = StorageSettings(database_path=root / "quietward.sqlite3", alert_log_path=root / "alerts.jsonl"); now = datetime(2026, 8, 7, 22, 0, tzinfo=timezone.utc); event = SecurityEvent("socket", now, "host", "test", EventKind.NEW_LISTENING_PORT, "shared-subject"); report = SentinelPipeline().analyze([event]); finding_id = report.findings[0].finding_id
            with ProductSentinelStore(settings) as store:
                store.persist_cycle(CollectionBatch(CollectorSnapshot(now, "host"), (event,)), report, started_at=now, completed_at=now); store.set_finding_state(finding_id, "expected", create_rule=True); store.set_finding_state(finding_id, "open"); kept, suppressed = store.filter_suppressed_events([event], now=now); self.assertEqual([item.event_id for item in kept], ["socket"]); self.assertEqual(suppressed, [])

    def test_legacy_empty_kind_rule_is_recovered_from_source_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); settings = StorageSettings(database_path=root / "quietward.sqlite3", alert_log_path=root / "alerts.jsonl"); now = datetime(2026, 8, 7, 22, 0, tzinfo=timezone.utc); socket = SecurityEvent("socket", now, "host", "test", EventKind.NEW_LISTENING_PORT, "shared-subject"); report = SentinelPipeline().analyze([socket]); finding_id = report.findings[0].finding_id
            with SentinelStore(settings) as legacy:
                legacy.persist_cycle(CollectionBatch(CollectorSnapshot(now, "host"), (socket,)), report, started_at=now, completed_at=now); legacy.set_finding_state(finding_id, "expected", create_rule=True)
            unrelated = SecurityEvent("process", now, "host", "test", EventKind.PROCESS_START, "shared-subject")
            with ProductSentinelStore(settings) as store:
                kept, suppressed = store.filter_suppressed_events([socket, unrelated], now=now); self.assertEqual([item.event_id for item in suppressed], ["socket"]); self.assertEqual([item.event_id for item in kept], ["process"])


if __name__ == "__main__": unittest.main()
