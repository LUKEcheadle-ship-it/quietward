from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from .finding_lifecycle import (
    IncidentIdentity,
    LifecycleRecord,
    LifecycleState,
    build_incident_identity,
    observe_incident,
    resolve_absent_incidents,
)


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("lifecycle timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("stored lifecycle timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _json_list(values: Iterable[str]) -> str:
    return json.dumps(sorted(set(values)), separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class LifecycleCycleSummary:
    cycle_id: int
    new: int
    recurring: int
    changed: int
    resolved: int
    active_total: int
    coverage_complete: bool
    already_processed: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "cycle_id": self.cycle_id,
            "new": self.new,
            "recurring": self.recurring,
            "changed": self.changed,
            "resolved": self.resolved,
            "active_total": self.active_total,
            "coverage_complete": self.coverage_complete,
            "already_processed": self.already_processed,
            "actions_executed": 0,
        }


class IncidentLifecycleRepository:
    """Forward-only SQLite persistence for QuietWard incident lifecycle state."""

    SCHEMA_VERSION = 1
    DEFAULT_MAX_TRANSITIONS = 5_000
    DEFAULT_MAX_RESOLVED_INCIDENTS = 10_000

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        max_transitions: int = DEFAULT_MAX_TRANSITIONS,
        max_resolved_incidents: int = DEFAULT_MAX_RESOLVED_INCIDENTS,
    ) -> None:
        if max_transitions <= 0:
            raise ValueError("max_transitions must be positive")
        if max_resolved_incidents < 0:
            raise ValueError("max_resolved_incidents must not be negative")
        self.connection = connection
        self.max_transitions = int(max_transitions)
        self.max_resolved_incidents = int(max_resolved_incidents)
        self.connection.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    def _migrate(self) -> None:
        with self.connection:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS incident_lifecycle(
                    incident_key TEXT PRIMARY KEY,
                    signature TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score_band INTEGER NOT NULL,
                    event_kinds_json TEXT NOT NULL,
                    event_sources_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(
                        state IN ('new','recurring','changed','resolved')
                    ),
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    resolved_at TEXT,
                    cycles_seen INTEGER NOT NULL CHECK(cycles_seen>=1),
                    occurrences INTEGER NOT NULL CHECK(occurrences>=1),
                    active INTEGER NOT NULL CHECK(active IN (0,1)),
                    last_cycle_id INTEGER NOT NULL CHECK(last_cycle_id>=1)
                );
                CREATE INDEX IF NOT EXISTS idx_incident_lifecycle_active
                    ON incident_lifecycle(active, last_seen DESC);
                CREATE INDEX IF NOT EXISTS idx_incident_lifecycle_state
                    ON incident_lifecycle(state, last_seen DESC);
                CREATE TABLE IF NOT EXISTS incident_lifecycle_transitions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_key TEXT NOT NULL,
                    cycle_id INTEGER NOT NULL CHECK(cycle_id>=1),
                    state TEXT NOT NULL CHECK(
                        state IN ('new','recurring','changed','resolved')
                    ),
                    observed_at TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    UNIQUE(incident_key, cycle_id),
                    FOREIGN KEY(incident_key)
                        REFERENCES incident_lifecycle(incident_key) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_incident_transitions_cycle
                    ON incident_lifecycle_transitions(cycle_id DESC, id DESC);
                CREATE TABLE IF NOT EXISTS incident_lifecycle_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            self.connection.execute(
                """
                INSERT INTO incident_lifecycle_meta(key,value)
                VALUES('schema_version',?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (str(self.SCHEMA_VERSION),),
            )

    def _meta(self, key: str) -> str | None:
        row = self.connection.execute(
            "SELECT value FROM incident_lifecycle_meta WHERE key=?",
            (key,),
        ).fetchone()
        return str(row[0]) if row else None

    def _set_meta(self, key: str, value: str) -> None:
        self.connection.execute(
            """
            INSERT INTO incident_lifecycle_meta(key,value) VALUES(?,?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (key, value),
        )

    def last_processed_cycle_id(self) -> int:
        raw = self._meta("last_processed_cycle_id")
        return int(raw) if raw is not None else 0

    def _record_from_row(self, row: sqlite3.Row | Sequence[object]) -> LifecycleRecord:
        identity = IncidentIdentity(
            incident_key=str(row[0]),
            signature=str(row[1]),
            finding_id=str(row[2]),
            host_id=str(row[3]),
            subject=str(row[4]),
            severity=str(row[5]),
            score_band=int(row[6]),
            event_kinds=tuple(json.loads(str(row[7]))),
            event_sources=tuple(json.loads(str(row[8]))),
        )
        first_seen = _parse_utc(str(row[10]))
        last_seen = _parse_utc(str(row[11]))
        if first_seen is None or last_seen is None:
            raise ValueError("stored lifecycle record is missing required timestamps")
        return LifecycleRecord(
            identity=identity,
            state=LifecycleState(str(row[9])),
            first_seen=first_seen,
            last_seen=last_seen,
            resolved_at=_parse_utc(str(row[12])) if row[12] is not None else None,
            cycles_seen=int(row[13]),
            occurrences=int(row[14]),
            active=bool(row[15]),
        )

    def _rows(self) -> list[sqlite3.Row | Sequence[object]]:
        return self.connection.execute(
            """
            SELECT incident_key,signature,finding_id,host_id,subject,severity,
                   score_band,event_kinds_json,event_sources_json,state,
                   first_seen,last_seen,resolved_at,cycles_seen,occurrences,
                   active,last_cycle_id
            FROM incident_lifecycle
            """
        ).fetchall()

    def load_records(self) -> dict[str, LifecycleRecord]:
        records: dict[str, LifecycleRecord] = {}
        for row in self._rows():
            record = self._record_from_row(row)
            records[record.identity.incident_key] = record
        return records

    def _upsert_record(self, record: LifecycleRecord, cycle_id: int) -> None:
        identity = record.identity
        self.connection.execute(
            """
            INSERT INTO incident_lifecycle(
                incident_key,signature,finding_id,host_id,subject,severity,
                score_band,event_kinds_json,event_sources_json,state,
                first_seen,last_seen,resolved_at,cycles_seen,occurrences,
                active,last_cycle_id
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(incident_key) DO UPDATE SET
                signature=excluded.signature,
                finding_id=excluded.finding_id,
                host_id=excluded.host_id,
                subject=excluded.subject,
                severity=excluded.severity,
                score_band=excluded.score_band,
                event_kinds_json=excluded.event_kinds_json,
                event_sources_json=excluded.event_sources_json,
                state=excluded.state,
                first_seen=excluded.first_seen,
                last_seen=excluded.last_seen,
                resolved_at=excluded.resolved_at,
                cycles_seen=excluded.cycles_seen,
                occurrences=excluded.occurrences,
                active=excluded.active,
                last_cycle_id=excluded.last_cycle_id
            """,
            (
                identity.incident_key,
                identity.signature,
                identity.finding_id,
                identity.host_id,
                identity.subject,
                identity.severity,
                identity.score_band,
                _json_list(identity.event_kinds),
                _json_list(identity.event_sources),
                record.state.value,
                _utc(record.first_seen),
                _utc(record.last_seen),
                _utc(record.resolved_at) if record.resolved_at else None,
                record.cycles_seen,
                record.occurrences,
                int(record.active),
                cycle_id,
            ),
        )

    def _transition(self, record: LifecycleRecord, cycle_id: int, observed_at: datetime) -> None:
        self.connection.execute(
            """
            INSERT OR IGNORE INTO incident_lifecycle_transitions(
                incident_key,cycle_id,state,observed_at,finding_id,signature
            ) VALUES(?,?,?,?,?,?)
            """,
            (
                record.identity.incident_key,
                cycle_id,
                record.state.value,
                _utc(observed_at),
                record.identity.finding_id,
                record.identity.signature,
            ),
        )

    def _prune_locked(self) -> None:
        self.connection.execute(
            """
            DELETE FROM incident_lifecycle_transitions
            WHERE id NOT IN (
                SELECT id FROM incident_lifecycle_transitions
                ORDER BY id DESC LIMIT ?
            )
            """,
            (self.max_transitions,),
        )
        cursor = self.connection.execute(
            """
            DELETE FROM incident_lifecycle
            WHERE active=0 AND incident_key NOT IN (
                SELECT incident_key FROM incident_lifecycle
                WHERE active=0
                ORDER BY resolved_at DESC,last_seen DESC
                LIMIT ?
            )
            """,
            (self.max_resolved_incidents,),
        )
        pruned = max(0, int(cursor.rowcount))
        if pruned > 0:
            previous = int(self._meta("pruned_resolved_incidents") or 0)
            self._set_meta("pruned_resolved_incidents", str(previous + pruned))

    def reconcile_cycle(
        self,
        cycle_id: int,
        findings: Iterable[Mapping[str, Any]],
        events: Iterable[Mapping[str, Any]],
        *,
        observed_at: datetime,
        coverage_complete: bool,
    ) -> LifecycleCycleSummary:
        if cycle_id <= 0:
            raise ValueError("cycle_id must be positive")
        _utc(observed_at)
        last_processed = self.last_processed_cycle_id()
        if cycle_id <= last_processed:
            return LifecycleCycleSummary(
                cycle_id=cycle_id,
                new=0,
                recurring=0,
                changed=0,
                resolved=0,
                active_total=self.active_count(),
                coverage_complete=coverage_complete,
                already_processed=True,
            )
        if last_processed and cycle_id != last_processed + 1:
            raise ValueError(
                f"lifecycle cycle gap: expected {last_processed + 1}, got {cycle_id}"
            )

        event_values = [dict(item) for item in events]
        records = self.load_records()
        seen: set[str] = set()
        updated: dict[str, LifecycleRecord] = {}
        state_counts = {state: 0 for state in LifecycleState}

        for finding in findings:
            identity = build_incident_identity(finding, event_values)
            previous = records.get(identity.incident_key)
            record = observe_incident(previous, identity, observed_at=observed_at)
            records[identity.incident_key] = record
            updated[identity.incident_key] = record
            seen.add(identity.incident_key)
            state_counts[record.state] += 1

        resolved_records = resolve_absent_incidents(
            records,
            seen,
            completed_at=observed_at,
            coverage_complete=coverage_complete,
        )
        for incident_key, record in resolved_records.items():
            previous = records.get(incident_key)
            if (
                previous is not None
                and previous.active
                and not record.active
                and record.state == LifecycleState.RESOLVED
            ):
                updated[incident_key] = record
                state_counts[LifecycleState.RESOLVED] += 1
        records = resolved_records

        with self.connection:
            for incident_key, record in updated.items():
                self._upsert_record(record, cycle_id)
                self._transition(record, cycle_id, observed_at)
            self._set_meta("last_processed_cycle_id", str(cycle_id))
            self._prune_locked()

        return LifecycleCycleSummary(
            cycle_id=cycle_id,
            new=state_counts[LifecycleState.NEW],
            recurring=state_counts[LifecycleState.RECURRING],
            changed=state_counts[LifecycleState.CHANGED],
            resolved=state_counts[LifecycleState.RESOLVED],
            active_total=self.active_count(),
            coverage_complete=coverage_complete,
        )

    def catch_up_from_evidence_chain(self, *, up_to_cycle_id: int | None = None) -> int:
        last_processed = self.last_processed_cycle_id()
        params: list[object] = [last_processed]
        query = "SELECT cycle_id,payload_json FROM evidence_chain WHERE cycle_id>?"
        if up_to_cycle_id is not None:
            query += " AND cycle_id<=?"
            params.append(up_to_cycle_id)
        query += " ORDER BY cycle_id"
        rows = self.connection.execute(query, tuple(params)).fetchall()
        if not rows:
            return 0

        first_cycle = int(rows[0][0])
        if last_processed == 0 and first_cycle > 1 and not self.load_records():
            with self.connection:
                self._set_meta("history_floor_cycle_id", str(first_cycle - 1))
                self._set_meta("last_processed_cycle_id", str(first_cycle - 1))

        replayed = 0
        for row in rows:
            cycle_id = int(row[0])
            payload = json.loads(str(row[1]))
            report = payload.get("report") or {}
            findings = report.get("findings") or []
            events = payload.get("events") or []
            raw_completed = str(payload.get("completed_at") or "")
            completed_at = _parse_utc(raw_completed)
            if completed_at is None:
                raise ValueError(f"cycle {cycle_id}: completed_at is missing")
            self.reconcile_cycle(
                cycle_id,
                findings,
                events,
                observed_at=completed_at,
                coverage_complete=False,
            )
            replayed += 1
        return replayed

    def active_count(self) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) FROM incident_lifecycle WHERE active=1"
        ).fetchone()
        return int(row[0]) if row else 0

    def summary(self) -> dict[str, object]:
        states = {
            str(row[0]): int(row[1])
            for row in self.connection.execute(
                "SELECT state,COUNT(*) FROM incident_lifecycle GROUP BY state"
            )
        }
        row = self.connection.execute(
            "SELECT COUNT(*),SUM(active) FROM incident_lifecycle"
        ).fetchone()
        transition_row = self.connection.execute(
            "SELECT COUNT(*) FROM incident_lifecycle_transitions"
        ).fetchone()
        return {
            "schema_version": self.SCHEMA_VERSION,
            "incidents": int(row[0]) if row else 0,
            "active": int(row[1] or 0) if row else 0,
            "states": states,
            "transitions": int(transition_row[0]) if transition_row else 0,
            "last_processed_cycle_id": self.last_processed_cycle_id(),
            "history_floor_cycle_id": int(self._meta("history_floor_cycle_id") or 0),
            "pruned_resolved_incidents": int(self._meta("pruned_resolved_incidents") or 0),
            "retention": {
                "max_transitions": self.max_transitions,
                "max_resolved_incidents": self.max_resolved_incidents,
            },
            "actions_executed": 0,
        }

    def recent_incidents(
        self,
        *,
        limit: int = 100,
        active_only: bool = False,
    ) -> list[dict[str, object]]:
        bounded = max(1, min(int(limit), 1000))
        where = "WHERE active=1" if active_only else ""
        rows = self.connection.execute(
            f"""
            SELECT incident_key,signature,finding_id,host_id,subject,severity,
                   score_band,event_kinds_json,event_sources_json,state,
                   first_seen,last_seen,resolved_at,cycles_seen,occurrences,
                   active,last_cycle_id
            FROM incident_lifecycle {where}
            ORDER BY active DESC,last_seen DESC LIMIT ?
            """,
            (bounded,),
        ).fetchall()
        result: list[dict[str, object]] = []
        for row in rows:
            record = self._record_from_row(row)
            value = record.to_dict()
            value["last_cycle_id"] = int(row[16])
            result.append(value)
        return result

    def recent_transitions(self, limit: int = 100) -> list[dict[str, object]]:
        bounded = max(1, min(int(limit), 1000))
        rows = self.connection.execute(
            """
            SELECT incident_key,cycle_id,state,observed_at,finding_id,signature
            FROM incident_lifecycle_transitions
            ORDER BY cycle_id DESC,id DESC LIMIT ?
            """,
            (bounded,),
        ).fetchall()
        return [
            {
                "incident_key": str(row[0]),
                "cycle_id": int(row[1]),
                "state": str(row[2]),
                "observed_at": str(row[3]),
                "finding_id": str(row[4]),
                "signature": str(row[5]),
            }
            for row in rows
        ]
