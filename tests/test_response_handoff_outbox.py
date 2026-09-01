from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from quietward.contracts import (
    ActionProposal,
    ActionType,
    AnalysisReport,
    EventAssessment,
    EventKind,
    Finding,
    SecurityEvent,
    Severity,
)
from quietward.privacy_identity import PrivacyIdentity
from run_response_handoff_outbox import OutboxError, export_once


def _cycle_payload(subject: str = "/private/example.bin", *, with_finding: bool = True) -> dict:
    observed = datetime(2026, 8, 31, 21, 0, tzinfo=timezone.utc)
    event = SecurityEvent(
        event_id="event-outbox-1",
        observed_at=observed,
        host_id="host-outbox",
        source="filesystem",
        kind=EventKind.EXECUTABLE_CREATED,
        subject=subject,
        attributes={"owner_executable": "/usr/bin/python3"},
        confidence=0.9,
    )
    assessment = EventAssessment(
        event_id=event.event_id,
        score=75.0,
        severity=Severity.HIGH,
        reasons=("known_signal",),
    )
    findings = ()
    proposals = ()
    if with_finding:
        finding = Finding(
            finding_id="qwf-outbox-1",
            created_at=observed,
            host_id=event.host_id,
            subject=subject,
            title="Synthetic outbox finding",
            summary="Synthetic outbox summary",
            score=75.0,
            severity=Severity.HIGH,
            evidence_event_ids=(event.event_id,),
            reasons=("correlation_evidence_bonus=+4.0",),
        )
        findings = (finding,)
        proposals = (
            ActionProposal(
                proposal_id="fsp-outbox-1",
                finding_id=finding.finding_id,
                action_type=ActionType.COLLECT_DIAGNOSTIC,
                target=subject,
                reason="local proposal",
                destructive=False,
                executable_in_current_mode=False,
            ),
        )
    report = AnalysisReport(
        generated_at=observed,
        mode="observe_only",
        events_analyzed=1,
        assessments=(assessment,),
        findings=findings,
        action_proposals=proposals,
        actions_executed=0,
    )
    return {
        "started_at": observed.isoformat(),
        "completed_at": observed.isoformat(),
        "events": [event.to_dict()],
        "report": report.to_dict(),
    }


def _database(path: Path, rows: list[tuple[int, dict]]) -> dict[int, str]:
    hashes: dict[int, str] = {}
    previous = "0" * 64
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        connection.execute(
            """
            CREATE TABLE evidence_chain(
                cycle_id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                chain_hash TEXT NOT NULL UNIQUE,
                payload_json TEXT NOT NULL
            )
            """
        )
        for cycle_id, payload in rows:
            payload_json = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()
            chain_hash = hashlib.sha256(
                f"{previous}|{payload_hash}|{cycle_id}".encode()
            ).hexdigest()
            connection.execute(
                "INSERT INTO evidence_chain(cycle_id,timestamp,previous_hash,payload_hash,chain_hash,payload_json) VALUES(?,?,?,?,?,?)",
                (
                    cycle_id,
                    datetime.now(timezone.utc).isoformat(),
                    previous,
                    payload_hash,
                    chain_hash,
                    payload_json,
                ),
            )
            hashes[cycle_id] = chain_hash
            previous = chain_hash
        connection.commit()
    return hashes


def _zero_state() -> dict:
    return {
        "format": "quietward-response-outbox-state-v1",
        "last_cycle_id": 0,
        "last_chain_hash": None,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "network_requests_performed": 0,
        "actions_executed": 0,
    }


class ResponseHandoffOutboxTests(unittest.TestCase):
    def test_outbox_exports_sanitized_finding_once_and_advances_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "quietward.sqlite3"
            outbox = root / "outbox"
            subject = "/home/alice/private/payroll.xlsx"
            hashes = _database(
                database,
                [
                    (1, _cycle_payload(with_finding=False)),
                    (2, _cycle_payload(subject)),
                ],
            )
            identity = PrivacyIdentity(b"k" * 32)

            first = export_once(database, outbox, identity, max_pending_files=10)
            self.assertEqual(first["cycles_advanced"], 2)
            self.assertEqual(first["handoffs_exported"], 1)
            self.assertEqual(first["cycles_without_findings"], 1)
            self.assertEqual(first["last_cycle_id"], 2)

            files = list(outbox.glob("cycle-*.json"))
            self.assertEqual(len(files), 1)
            text = files[0].read_text(encoding="utf-8")
            self.assertNotIn(subject, text)
            self.assertNotIn("/usr/bin/python3", text)
            self.assertNotIn("qwf-outbox-1", text)
            document = json.loads(text)
            self.assertEqual(document["source_cycle_id"], 2)
            self.assertEqual(document["source_chain_hash"], hashes[2])
            self.assertIs(document["safety"]["observation_only_source"], True)
            self.assertIs(document["safety"]["executable_authority"], False)
            self.assertEqual(document["safety"]["actions_executed"], 0)
            event = document["events"][0]
            self.assertEqual(event["metadata"]["quietward_source_cycle_id"], 2)
            self.assertEqual(event["metadata"]["quietward_source_chain_hash"], hashes[2])
            self.assertRegex(
                event["metadata"]["quietward_finding_hmac_sha256"],
                r"^[0-9a-f]{32}$",
            )

            second = export_once(database, outbox, identity, max_pending_files=10)
            self.assertEqual(second["cycles_advanced"], 0)
            self.assertEqual(second["handoffs_exported"], 0)
            self.assertEqual(len(list(outbox.glob("cycle-*.json"))), 1)

    def test_outbox_fails_closed_if_existing_cycle_file_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "quietward.sqlite3"
            outbox = root / "outbox"
            _database(database, [(1, _cycle_payload())])
            identity = PrivacyIdentity(b"k" * 32)
            export_once(database, outbox, identity, max_pending_files=10)

            state = outbox / ".quietward-response-outbox-state.json"
            state.write_text(json.dumps(_zero_state()), encoding="utf-8")
            handoff = next(outbox.glob("cycle-*.json"))
            handoff.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(OutboxError, "changed unexpectedly"):
                export_once(database, outbox, identity, max_pending_files=10)

    def test_outbox_stops_when_pending_capacity_is_reached(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "quietward.sqlite3"
            outbox = root / "outbox"
            _database(
                database,
                [
                    (1, _cycle_payload("/private/one")),
                    (2, _cycle_payload("/private/two")),
                ],
            )
            with self.assertRaisesRegex(OutboxError, "outbox is full"):
                export_once(database, outbox, PrivacyIdentity(b"k" * 32), max_pending_files=1)
            self.assertEqual(len(list(outbox.glob("cycle-*.json"))), 1)

    def test_outbox_refuses_tampered_quietward_evidence_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "quietward.sqlite3"
            outbox = root / "outbox"
            _database(database, [(1, _cycle_payload())])
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "UPDATE evidence_chain SET payload_json=? WHERE cycle_id=1",
                    (json.dumps({"tampered": True}),),
                )
                connection.commit()
            with self.assertRaisesRegex(OutboxError, "evidence chain failed"):
                export_once(database, outbox, PrivacyIdentity(b"k" * 32), max_pending_files=10)

    def test_outbox_state_hash_must_match_quietward_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "quietward.sqlite3"
            outbox = root / "outbox"
            hashes = _database(database, [(1, _cycle_payload())])
            export_once(database, outbox, PrivacyIdentity(b"k" * 32), max_pending_files=10)
            state_path = outbox / ".quietward-response-outbox-state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["last_chain_hash"], hashes[1])
            state["last_chain_hash"] = "f" * 64
            state_path.write_text(json.dumps(state), encoding="utf-8")
            with self.assertRaisesRegex(OutboxError, "state chain hash does not match"):
                export_once(database, outbox, PrivacyIdentity(b"k" * 32), max_pending_files=10)


if __name__ == "__main__":
    unittest.main()
