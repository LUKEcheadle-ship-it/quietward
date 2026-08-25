from __future__ import annotations

import hashlib
import base64
import json
import sqlite3
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .collectors import CollectionBatch, CollectorSnapshot
from .config import StorageSettings
from .contracts import AnalysisReport, EventKind, SecurityEvent
from .evidence import EvidenceSigner
from .exports import build_redacted_incident_export


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True, slots=True)
class PersistResult:
    events_inserted: int
    findings_inserted: int
    proposals_inserted: int
    snapshot_id: int
    cycle_id: int
    chain_hash: str | None = None
    signature: str | None = None


class SentinelStore(AbstractContextManager["SentinelStore"]):
    SCHEMA_VERSION = 4
    REVIEW_STATES = {"open", "acknowledged", "resolved", "expected", "suppressed"}
    UNSUPPRESSIBLE_KINDS = {
        EventKind.MALWARE_SIGNATURE,
        EventKind.YARA_MATCH,
        EventKind.SELF_INTEGRITY_CHANGE,
        EventKind.EVIDENCE_INTEGRITY_FAILURE,
    }

    def __init__(self, settings: StorageSettings) -> None:
        self.settings = settings
        settings.database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            settings.database_path.parent.chmod(0o700)
        except OSError:
            pass
        self.signer = (
            EvidenceSigner.load(
                settings.evidence_signing_key_path,
                key_id_namespace=settings.evidence_signing_key_namespace,
            )
            if settings.evidence_signing_key_path is not None
            else None
        )
        self.connection = sqlite3.connect(settings.database_path, timeout=10.0)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA busy_timeout=10000")
        try:
            self._migrate()
            self._configure_signing()
        except Exception:
            self.connection.close()
            raise
        try:
            settings.database_path.chmod(0o600)
        except OSError:
            pass

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def close(self) -> None:
        self.connection.close()

    def _migrate(self) -> None:
        with self.connection:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cycles(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    events_count INTEGER NOT NULL,
                    findings_count INTEGER NOT NULL,
                    actions_executed INTEGER NOT NULL,
                    error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_cycles_completed_at
                    ON cycles(completed_at DESC);
                CREATE TABLE IF NOT EXISTS snapshots(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    observed_at TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    collector_version TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_snapshots_observed_at
                    ON snapshots(observed_at DESC);
                CREATE TABLE IF NOT EXISTS events(
                    event_id TEXT PRIMARY KEY,
                    observed_at TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    severity TEXT,
                    score REAL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_observed_at
                    ON events(observed_at DESC);
                CREATE INDEX IF NOT EXISTS idx_events_kind
                    ON events(kind, observed_at DESC);
                CREATE TABLE IF NOT EXISTS findings(
                    finding_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score REAL NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_findings_created_at
                    ON findings(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_findings_severity
                    ON findings(severity, created_at DESC);
                CREATE TABLE IF NOT EXISTS proposals(
                    proposal_id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    executable INTEGER NOT NULL CHECK(executable=0),
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS alerts(
                    finding_id TEXT PRIMARY KEY,
                    emitted_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS scanner_runs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scanner TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    target TEXT,
                    events_count INTEGER NOT NULL,
                    returncode INTEGER,
                    error TEXT,
                    metadata_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_scanner_runs
                    ON scanner_runs(scanner, completed_at DESC);
                CREATE TABLE IF NOT EXISTS finding_reviews(
                    finding_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL CHECK(
                        state IN ('open','acknowledged','resolved','expected','suppressed')
                    ),
                    note TEXT,
                    suppress_until TEXT,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS suppression_rules(
                    rule_id TEXT PRIMARY KEY,
                    source_finding_id TEXT,
                    subject TEXT NOT NULL,
                    kinds_json TEXT NOT NULL,
                    expires_at TEXT,
                    reason TEXT,
                    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(source_finding_id)
                        REFERENCES findings(finding_id) ON DELETE SET NULL
                );
                CREATE INDEX IF NOT EXISTS idx_suppression_active
                    ON suppression_rules(enabled, expires_at);
                CREATE TABLE IF NOT EXISTS evidence_chain(
                    cycle_id INTEGER PRIMARY KEY,
                    previous_hash TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    chain_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(cycle_id) REFERENCES cycles(id) ON DELETE RESTRICT
                );
                CREATE TABLE IF NOT EXISTS evidence_signatures(
                    cycle_id INTEGER PRIMARY KEY,
                    algorithm TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(cycle_id) REFERENCES evidence_chain(cycle_id) ON DELETE CASCADE
                );
                """
            )
            self.set_metadata("schema_version", str(self.SCHEMA_VERSION))

    def _configure_signing(self) -> None:
        configured_key_id = self.get_metadata("evidence_signing_key_id")
        if configured_key_id is not None:
            if self.signer is not None and self.signer.key_id != configured_key_id:
                raise ValueError("configured evidence signing key does not match the database")
            return
        if self.signer is None:
            return
        row = self.connection.execute("SELECT COALESCE(MAX(id), 0) FROM cycles").fetchone()
        required_from = int(row[0]) + 1
        with self.connection:
            self.set_metadata("evidence_signing_key_id", self.signer.key_id)
            self.set_metadata("evidence_signing_algorithm", self.signer.algorithm)
            self.set_metadata("evidence_signature_required_from_cycle", str(required_from))

    def set_metadata(self, key: str, value: str) -> None:
        self.connection.execute(
            """
            INSERT INTO metadata(key,value) VALUES(?,?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (key, value),
        )

    def get_metadata(self, key: str) -> str | None:
        row = self.connection.execute(
            "SELECT value FROM metadata WHERE key=?",
            (key,),
        ).fetchone()
        return str(row[0]) if row else None

    def get_integrity_manifest(self) -> dict[str, dict[str, object]] | None:
        raw = self.get_metadata("self_integrity_manifest")
        if not raw:
            return None
        value = json.loads(raw)
        return value if isinstance(value, dict) else None

    def set_integrity_manifest(self, manifest: dict[str, dict[str, object]]) -> None:
        with self.connection:
            self.set_metadata("self_integrity_manifest", _json(manifest))

    def _chain_payload(
        self,
        batch: CollectionBatch,
        report: AnalysisReport,
        *,
        started_at: datetime,
        completed_at: datetime,
        status: str,
        error: str | None,
    ) -> str:
        return _json(
            {
                "started_at": _utc(started_at),
                "completed_at": _utc(completed_at),
                "status": status,
                "error": error,
                "snapshot": batch.snapshot.to_dict(),
                "events": [event.to_dict() for event in batch.events],
                "report": report.to_dict(),
            }
        )

    def _signing_required_from_cycle(self) -> int | None:
        raw = self.get_metadata("evidence_signature_required_from_cycle")
        return int(raw) if raw is not None else None

    def _chain_anchor(self) -> tuple[int, str]:
        cycle_raw = self.get_metadata("evidence_chain_anchor_cycle")
        hash_value = self.get_metadata("evidence_chain_anchor_hash")
        if cycle_raw is None or hash_value is None:
            return 0, "0" * 64
        return int(cycle_raw), hash_value

    def persist_cycle(
        self,
        batch: CollectionBatch,
        report: AnalysisReport,
        *,
        started_at: datetime,
        completed_at: datetime,
        status: str = "ok",
        error: str | None = None,
    ) -> PersistResult:
        if report.actions_executed != 0:
            raise ValueError("observation-only reports must execute zero actions")
        required_from = self._signing_required_from_cycle()
        if required_from is not None and self.signer is None:
            raise ValueError("evidence signing key is required for new cycles")

        assessment_by_id = {item.event_id: item for item in report.assessments}
        created = _utc_now()
        events_inserted = findings_inserted = proposals_inserted = 0
        signature: str | None = None

        with self.connection:
            cursor = self.connection.execute(
                """
                INSERT INTO cycles(
                    started_at,completed_at,status,events_count,
                    findings_count,actions_executed,error
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    _utc(started_at),
                    _utc(completed_at),
                    status,
                    len(batch.events),
                    len(report.findings),
                    0,
                    error,
                ),
            )
            cycle_id = int(cursor.lastrowid)
            cursor = self.connection.execute(
                """
                INSERT INTO snapshots(
                    observed_at,host_id,collector_version,payload_json,created_at
                ) VALUES(?,?,?,?,?)
                """,
                (
                    batch.snapshot.to_dict()["observed_at"],
                    batch.snapshot.host_id,
                    batch.snapshot.collector_version,
                    _json(batch.snapshot.to_dict()),
                    created,
                ),
            )
            snapshot_id = int(cursor.lastrowid)

            for event in batch.events:
                assessment = assessment_by_id.get(event.event_id)
                result = self.connection.execute(
                    """
                    INSERT OR IGNORE INTO events(
                        event_id,observed_at,host_id,source,kind,subject,
                        severity,score,payload_json,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        event.event_id,
                        event.to_dict()["observed_at"],
                        event.host_id,
                        event.source,
                        event.kind.value,
                        event.subject,
                        assessment.severity.value if assessment else None,
                        assessment.score if assessment else None,
                        _json(event.to_dict()),
                        created,
                    ),
                )
                events_inserted += int(result.rowcount > 0)

            for finding in report.findings:
                result = self.connection.execute(
                    """
                    INSERT OR IGNORE INTO findings(
                        finding_id,created_at,host_id,subject,severity,score,payload_json
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        finding.finding_id,
                        finding.to_dict()["created_at"],
                        finding.host_id,
                        finding.subject,
                        finding.severity.value,
                        finding.score,
                        _json(finding.to_dict()),
                    ),
                )
                findings_inserted += int(result.rowcount > 0)

            for proposal in report.action_proposals:
                if proposal.executable_in_current_mode:
                    raise ValueError("executable proposals are forbidden")
                result = self.connection.execute(
                    """
                    INSERT OR IGNORE INTO proposals(
                        proposal_id,finding_id,action_type,executable,
                        payload_json,created_at
                    ) VALUES(?,?,?,?,?,?)
                    """,
                    (
                        proposal.proposal_id,
                        proposal.finding_id,
                        proposal.action_type.value,
                        0,
                        _json(proposal.to_dict()),
                        created,
                    ),
                )
                proposals_inserted += int(result.rowcount > 0)

            payload = self._chain_payload(
                batch,
                report,
                started_at=started_at,
                completed_at=completed_at,
                status=status,
                error=error,
            )
            payload_hash = hashlib.sha256(payload.encode()).hexdigest()
            row = self.connection.execute(
                "SELECT chain_hash FROM evidence_chain ORDER BY cycle_id DESC LIMIT 1"
            ).fetchone()
            if row:
                previous_hash = str(row[0])
            else:
                _, previous_hash = self._chain_anchor()
            chain_hash = hashlib.sha256(
                f"{previous_hash}|{payload_hash}|{cycle_id}".encode()
            ).hexdigest()
            self.connection.execute(
                """
                INSERT INTO evidence_chain(
                    cycle_id,previous_hash,payload_hash,chain_hash,payload_json,created_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    cycle_id,
                    previous_hash,
                    payload_hash,
                    chain_hash,
                    payload,
                    created,
                ),
            )
            if self.signer is not None:
                signature = self.signer.sign(cycle_id, chain_hash)
                self.connection.execute(
                    """
                    INSERT INTO evidence_signatures(
                        cycle_id,algorithm,key_id,signature,created_at
                    ) VALUES(?,?,?,?,?)
                    """,
                    (
                        cycle_id,
                        self.signer.algorithm,
                        self.signer.key_id,
                        signature,
                        created,
                    ),
                )

            self.set_metadata("last_cycle_at", created)
            self.set_metadata("last_cycle_status", status)
            self._prune_locked()

        return PersistResult(
            events_inserted,
            findings_inserted,
            proposals_inserted,
            snapshot_id,
            cycle_id,
            chain_hash,
            signature,
        )

    def verify_evidence_chain(self) -> dict[str, Any]:
        anchor_cycle, previous = self._chain_anchor()
        checked = 0
        signatures_checked = 0
        errors: list[str] = []
        configured_key_id = self.get_metadata("evidence_signing_key_id")
        configured_algorithm = self.get_metadata("evidence_signing_algorithm")
        required_from = self._signing_required_from_cycle()

        if configured_key_id is not None:
            if self.signer is None:
                errors.append("evidence signing key is required to verify signatures")
            elif self.signer.key_id != configured_key_id:
                errors.append("evidence signing key does not match the database")
            elif self.signer.algorithm != configured_algorithm:
                errors.append("evidence signing algorithm does not match the database")

        rows = self.connection.execute(
            """
            SELECT cycle_id,previous_hash,payload_hash,chain_hash,payload_json
            FROM evidence_chain ORDER BY cycle_id
            """
        )
        for row in rows:
            cycle_id = int(row[0])
            payload = str(row[4])
            payload_hash = hashlib.sha256(payload.encode()).hexdigest()
            expected = hashlib.sha256(
                f"{previous}|{payload_hash}|{cycle_id}".encode()
            ).hexdigest()
            if str(row[1]) != previous:
                errors.append(f"cycle {cycle_id}: previous hash mismatch")
            if str(row[2]) != payload_hash:
                errors.append(f"cycle {cycle_id}: payload hash mismatch")
            if str(row[3]) != expected:
                errors.append(f"cycle {cycle_id}: chain hash mismatch")

            if required_from is not None and cycle_id >= required_from:
                signature_row = self.connection.execute(
                    """
                    SELECT algorithm,key_id,signature
                    FROM evidence_signatures WHERE cycle_id=?
                    """,
                    (cycle_id,),
                ).fetchone()
                if signature_row is None:
                    errors.append(f"cycle {cycle_id}: evidence signature missing")
                else:
                    signatures_checked += 1
                    algorithm, key_id, signature = map(str, signature_row)
                    if algorithm != configured_algorithm:
                        errors.append(f"cycle {cycle_id}: signature algorithm mismatch")
                    if key_id != configured_key_id:
                        errors.append(f"cycle {cycle_id}: signature key mismatch")
                    if (
                        self.signer is not None
                        and self.signer.key_id == configured_key_id
                        and not self.signer.verify(cycle_id, str(row[3]), signature)
                    ):
                        errors.append(f"cycle {cycle_id}: signature mismatch")
            previous = str(row[3])
            checked += 1

        return {
            "valid": not errors,
            "cycles_checked": checked,
            "last_chain_hash": previous if checked else None,
            "anchor_cycle": anchor_cycle or None,
            "anchor_hash": previous if not checked and anchor_cycle else self.get_metadata(
                "evidence_chain_anchor_hash"
            ),
            "errors": errors[:100],
            "cryptographically_signed": configured_key_id is not None,
            "signature_algorithm": configured_algorithm,
            "signature_key_id": configured_key_id,
            "signature_required_from_cycle": required_from,
            "signatures_checked": signatures_checked,
        }

    def latest_snapshot(self) -> CollectorSnapshot | None:
        row = self.connection.execute(
            "SELECT payload_json FROM snapshots ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return CollectorSnapshot.from_dict(json.loads(row[0])) if row else None

    def record_scanner_run(self, value: dict[str, Any]) -> int:
        if value.get("actions_executed", 0) != 0:
            raise ValueError("scanner runs may not execute actions")
        with self.connection:
            cursor = self.connection.execute(
                """
                INSERT INTO scanner_runs(
                    scanner,started_at,completed_at,status,target,
                    events_count,returncode,error,metadata_json
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    value["scanner"],
                    value["started_at"],
                    value["completed_at"],
                    value["status"],
                    value.get("target"),
                    int(value.get("events_count", 0)),
                    value.get("returncode"),
                    value.get("error"),
                    _json(value),
                ),
            )
            self.set_metadata(
                f"scanner_last_run:{value['scanner']}",
                str(value["completed_at"]),
            )
            cutoff = _utc(
                datetime.now(timezone.utc)
                - timedelta(days=self.settings.retention_days)
            )
            self._prune_scanner_runs_locked(cutoff)
            return int(cursor.lastrowid)

    def scanner_last_run(self, scanner: str) -> datetime | None:
        raw = self.get_metadata(f"scanner_last_run:{scanner}")
        return datetime.fromisoformat(raw.replace("Z", "+00:00")) if raw else None

    def set_finding_state(
        self,
        finding_id: str,
        state: str,
        *,
        note: str | None = None,
        suppress_until: datetime | None = None,
        create_rule: bool = False,
    ) -> dict[str, Any]:
        if state not in self.REVIEW_STATES:
            raise ValueError(f"invalid finding state: {state}")
        row = self.connection.execute(
            "SELECT payload_json FROM findings WHERE finding_id=?",
            (finding_id,),
        ).fetchone()
        if not row:
            raise KeyError(f"unknown finding: {finding_id}")
        finding = json.loads(row[0])
        until = _utc(suppress_until) if suppress_until else None
        now = _utc_now()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO finding_reviews(
                    finding_id,state,note,suppress_until,updated_at
                ) VALUES(?,?,?,?,?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    state=excluded.state,
                    note=excluded.note,
                    suppress_until=excluded.suppress_until,
                    updated_at=excluded.updated_at
                """,
                (finding_id, state, (note or "")[:1000] or None, until, now),
            )
            if create_rule and state in {"expected", "suppressed"}:
                rule_id = "qwr-" + hashlib.sha256(
                    f"{finding_id}|{finding['subject']}|{until}".encode()
                ).hexdigest()[:16]
                self.connection.execute(
                    """
                    INSERT OR REPLACE INTO suppression_rules(
                        rule_id,source_finding_id,subject,kinds_json,
                        expires_at,reason,enabled,created_at
                    ) VALUES(?,?,?,?,?,?,1,?)
                    """,
                    (
                        rule_id,
                        finding_id,
                        finding["subject"],
                        "[]",
                        until,
                        (note or state)[:500],
                        now,
                    ),
                )
            if state == "open":
                self.connection.execute(
                    "UPDATE suppression_rules SET enabled=0 WHERE source_finding_id=?",
                    (finding_id,),
                )
        return self.finding_review(finding_id) or {"state": state}

    def finding_review(self, finding_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT state,note,suppress_until,updated_at
            FROM finding_reviews WHERE finding_id=?
            """,
            (finding_id,),
        ).fetchone()
        return dict(row) if row else None

    def filter_suppressed_events(
        self,
        events: Iterable[SecurityEvent],
        *,
        now: datetime | None = None,
    ) -> tuple[list[SecurityEvent], list[SecurityEvent]]:
        timestamp = _utc(now or datetime.now(timezone.utc))
        rows = self.connection.execute(
            """
            SELECT subject,kinds_json FROM suppression_rules
            WHERE enabled=1 AND (expires_at IS NULL OR expires_at>?)
            """,
            (timestamp,),
        ).fetchall()
        rules = [(str(row[0]), set(json.loads(row[1]))) for row in rows]
        kept: list[SecurityEvent] = []
        suppressed: list[SecurityEvent] = []
        for event in events:
            if event.kind in self.UNSUPPRESSIBLE_KINDS:
                kept.append(event)
                continue
            matched = any(
                event.subject == subject
                and (not kinds or event.kind.value in kinds)
                for subject, kinds in rules
            )
            (suppressed if matched else kept).append(event)
        return kept, suppressed

    def pending_alert_findings(
        self,
        severities: tuple[str, ...] = ("high", "critical"),
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        placeholders = ",".join("?" for _ in severities)
        now = _utc_now()
        rows = self.connection.execute(
            f"""
            SELECT f.payload_json
            FROM findings f
            LEFT JOIN alerts a ON a.finding_id=f.finding_id
            LEFT JOIN finding_reviews r ON r.finding_id=f.finding_id
            WHERE a.finding_id IS NULL
              AND f.severity IN ({placeholders})
              AND (
                r.state IS NULL
                OR r.state IN ('open','acknowledged')
                OR (r.state='suppressed' AND r.suppress_until<=?)
              )
            ORDER BY f.created_at LIMIT ?
            """,
            (*severities, now, limit),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def mark_alerted(self, finding: dict[str, Any]) -> None:
        with self.connection:
            self.connection.execute(
                """
                INSERT OR IGNORE INTO alerts(
                    finding_id,emitted_at,severity,payload_json
                ) VALUES(?,?,?,?)
                """,
                (
                    finding["finding_id"],
                    _utc_now(),
                    finding["severity"],
                    _json(finding),
                ),
            )

    def incident_bundle(self, finding_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT payload_json FROM findings WHERE finding_id=?",
            (finding_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown finding: {finding_id}")
        finding = json.loads(row[0])
        event_ids = tuple(str(item) for item in finding.get("evidence_event_ids", []))
        events: list[dict[str, Any]] = []
        for event_id in event_ids:
            event_row = self.connection.execute(
                "SELECT payload_json,severity,score FROM events WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if event_row is None:
                continue
            event = json.loads(event_row[0])
            event["assessment"] = {
                "severity": event_row[1],
                "score": event_row[2],
            }
            events.append(event)
        proposals = [
            json.loads(item[0])
            for item in self.connection.execute(
                """
                SELECT payload_json FROM proposals
                WHERE finding_id=? ORDER BY created_at,proposal_id
                """,
                (finding_id,),
            )
        ]
        return {
            "export_version": "quietward-incident-v1",
            "generated_at": _utc_now(),
            "finding": finding,
            "review": self.finding_review(finding_id)
            or {
                "state": "open",
                "note": None,
                "suppress_until": None,
                "updated_at": None,
            },
            "events": events,
            "proposals": proposals,
            "evidence_chain": self.verify_evidence_chain(),
            "actions_executed": 0,
        }

    @staticmethod
    def _feed_cursor(created_at: str, finding_id: str) -> str:
        raw = _json({"v": 1, "created_at": created_at, "finding_id": finding_id})
        return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")

    @staticmethod
    def _parse_feed_cursor(value: str | None) -> tuple[str, str] | None:
        if value is None:
            return None
        try:
            decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8")
            item = json.loads(decoded)
            if not isinstance(item, dict) or item.get("v") != 1:
                raise ValueError
            return str(item["created_at"]), str(item["finding_id"])
        except (ValueError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid findings-feed cursor") from exc

    def finding_feed(self, *, after: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        """Return versioned, redacted finding records in stable public order."""
        if not 1 <= limit <= 500:
            raise ValueError("findings-feed limit must be between 1 and 500")
        cursor = self._parse_feed_cursor(after)
        params: list[Any] = []
        where = ""
        if cursor is not None:
            where = "WHERE (created_at > ? OR (created_at = ? AND finding_id > ?))"
            params.extend((cursor[0], cursor[0], cursor[1]))
        rows = self.connection.execute(
            f"SELECT finding_id,created_at,payload_json FROM findings {where} ORDER BY created_at,finding_id LIMIT ?",
            (*params, limit),
        ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            bundle = self.incident_bundle(str(row["finding_id"]))
            redacted = build_redacted_incident_export(bundle)
            finding = redacted["finding"]
            events = redacted["events"]
            event = events[0] if events else {}
            output.append({"schema_version": "1.0", "cursor": self._feed_cursor(str(row["created_at"]), str(row["finding_id"])), "finding_id": finding["finding_id"], "observed_at": event.get("observed_at") or finding["created_at"], "host_id": finding["host_id"], "event_type": event.get("kind") or "unknown", "category": None, "severity": finding["severity"], "confidence": event.get("confidence", 0.0), "summary": finding["summary"], "evidence": {"events": events, "evidence_chain": redacted["evidence_chain"]}, "source": "quietward", "source_version": "1.0"})
        return output

    def summary(self) -> dict[str, Any]:
        def count(table: str) -> int:
            return int(
                self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            )

        severities = {
            str(row[0]): int(row[1])
            for row in self.connection.execute(
                "SELECT severity,COUNT(*) FROM findings GROUP BY severity"
            )
        }
        states = {
            str(row[0]): int(row[1])
            for row in self.connection.execute(
                "SELECT state,COUNT(*) FROM finding_reviews GROUP BY state"
            )
        }
        last = self.connection.execute(
            """
            SELECT completed_at,status,events_count,findings_count,
                   actions_executed,error
            FROM cycles ORDER BY id DESC LIMIT 1
            """
        ).fetchone()
        return {
            "schema_version": self.SCHEMA_VERSION,
            "cycles": count("cycles"),
            "snapshots": count("snapshots"),
            "events": count("events"),
            "findings": count("findings"),
            "proposals": count("proposals"),
            "alerts": count("alerts"),
            "scanner_runs": count("scanner_runs"),
            "suppression_rules": count("suppression_rules"),
            "evidence_signatures": count("evidence_signatures"),
            "findings_by_severity": severities,
            "finding_states": states,
            "evidence_chain": self.verify_evidence_chain(),
            "last_cycle": dict(last) if last else None,
            "actions_executed": 0,
        }

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        rows = self.connection.execute(
            """
            SELECT payload_json,severity,score
            FROM events ORDER BY observed_at DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        result = []
        for row in rows:
            item = json.loads(row[0])
            item["assessment"] = {"severity": row[1], "score": row[2]}
            result.append(item)
        return result

    def recent_findings(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        rows = self.connection.execute(
            """
            SELECT f.payload_json,r.state,r.note,r.suppress_until,r.updated_at
            FROM findings f
            LEFT JOIN finding_reviews r ON r.finding_id=f.finding_id
            ORDER BY f.created_at DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        result = []
        for row in rows:
            item = json.loads(row[0])
            item["review"] = {
                "state": row[1] or "open",
                "note": row[2],
                "suppress_until": row[3],
                "updated_at": row[4],
            }
            result.append(item)
        return result

    def _prune_locked(self) -> None:
        cutoff = _utc(datetime.now(timezone.utc) - timedelta(days=self.settings.retention_days))
        self.connection.execute("DELETE FROM snapshots WHERE created_at<?", (cutoff,))
        self.connection.execute("DELETE FROM events WHERE created_at<?", (cutoff,))
        self.connection.execute("DELETE FROM findings WHERE created_at<?", (cutoff,))
        self._keep_latest("snapshots", self.settings.max_snapshots)
        self._keep_latest("events", self.settings.max_events, "rowid")
        self._keep_latest("findings", self.settings.max_findings, "rowid")
        self._prune_scanner_runs_locked(cutoff)
        self._prune_cycles_locked(cutoff)

    def _prune_scanner_runs_locked(self, cutoff: str) -> None:
        self.connection.execute(
            "DELETE FROM scanner_runs WHERE completed_at<?",
            (cutoff,),
        )
        self._keep_latest(
            "scanner_runs",
            self.settings.max_scanner_runs,
        )

    def _prune_cycles_locked(self, cutoff: str) -> None:
        age_row = self.connection.execute(
            "SELECT MAX(id) FROM cycles WHERE completed_at<?",
            (cutoff,),
        ).fetchone()
        count_row = self.connection.execute(
            """
            SELECT MAX(id) FROM cycles
            WHERE id NOT IN (
                SELECT id FROM cycles ORDER BY id DESC LIMIT ?
            )
            """,
            (self.settings.max_cycles,),
        ).fetchone()
        delete_through = max(
            int(age_row[0]) if age_row and age_row[0] is not None else 0,
            int(count_row[0]) if count_row and count_row[0] is not None else 0,
        )
        if delete_through <= 0:
            return
        chain_row = self.connection.execute(
            """
            SELECT cycle_id,chain_hash FROM evidence_chain
            WHERE cycle_id<=? ORDER BY cycle_id DESC LIMIT 1
            """,
            (delete_through,),
        ).fetchone()
        if chain_row is not None:
            self.set_metadata("evidence_chain_anchor_cycle", str(chain_row[0]))
            self.set_metadata("evidence_chain_anchor_hash", str(chain_row[1]))
        self.connection.execute(
            "DELETE FROM evidence_signatures WHERE cycle_id<=?",
            (delete_through,),
        )
        self.connection.execute(
            "DELETE FROM evidence_chain WHERE cycle_id<=?",
            (delete_through,),
        )
        self.connection.execute(
            "DELETE FROM cycles WHERE id<=?",
            (delete_through,),
        )

    def _keep_latest(
        self,
        table: str,
        limit: int,
        id_column: str = "id",
    ) -> None:
        self.connection.execute(
            f"""
            DELETE FROM {table}
            WHERE {id_column} NOT IN (
                SELECT {id_column} FROM {table}
                ORDER BY {id_column} DESC LIMIT ?
            )
            """,
            (limit,),
        )


QuietWardStore = SentinelStore
