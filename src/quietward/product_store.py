from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable

from .contracts import EventKind, SecurityEvent
from .performance_store import PerformanceSentinelStore
from .suppression import event_bypasses_suppression


class ProductSentinelStore(PerformanceSentinelStore):
    """Performance store plus conservative product review semantics."""

    def __init__(self, *args, **kwargs) -> None:
        self._suppression_cache = None
        self._suppression_cache_data_version: int | None = None
        super().__init__(*args, **kwargs)

    def _invalidate_suppression_cache(self) -> None:
        self._suppression_cache = None
        self._suppression_cache_data_version = None

    def _finding_current_cycle_event_ids(self, finding_id: str) -> tuple[str, ...]:
        rows = self.connection.execute(
            """
            SELECT payload_json FROM evidence_chain
            ORDER BY cycle_id DESC
            """
        ).fetchall()
        for row in rows:
            try:
                payload = json.loads(str(row[0]))
            except (TypeError, json.JSONDecodeError):
                continue
            report = payload.get("report")
            if not isinstance(report, dict):
                continue
            findings = report.get("findings")
            if not isinstance(findings, list):
                continue
            if not any(
                isinstance(item, dict)
                and str(item.get("finding_id") or "") == finding_id
                for item in findings
            ):
                continue
            events = payload.get("events")
            if not isinstance(events, list):
                return ()
            return tuple(
                str(item.get("event_id") or "")
                for item in events
                if isinstance(item, dict) and str(item.get("event_id") or "").strip()
            )
        return ()

    def _finding_scoped_kinds(self, finding_id: str) -> tuple[str, ...]:
        row = self.connection.execute(
            "SELECT payload_json FROM findings WHERE finding_id=?",
            (finding_id,),
        ).fetchone()
        if row is None:
            return ()
        finding = json.loads(str(row[0]))
        evidence_ids = tuple(
            str(item)
            for item in finding.get("evidence_event_ids", ())
            if str(item).strip()
        )
        if not evidence_ids:
            return ()

        current_cycle_ids = set(self._finding_current_cycle_event_ids(finding_id))
        if not current_cycle_ids:
            return ()
        event_ids = tuple(item for item in evidence_ids if item in current_cycle_ids)
        if not event_ids:
            return ()

        placeholders = ",".join("?" for _ in event_ids)
        kinds = {
            str(item[0])
            for item in self.connection.execute(
                f"SELECT DISTINCT kind FROM events WHERE event_id IN ({placeholders})",
                event_ids,
            ).fetchall()
        }
        unsuppressible = {item.value for item in self.UNSUPPRESSIBLE_KINDS}
        return tuple(sorted(kind for kind in kinds if kind not in unsuppressible))

    def set_finding_state(
        self,
        finding_id: str,
        state: str,
        *,
        note: str | None = None,
        suppress_until: datetime | None = None,
        create_rule: bool = False,
    ) -> dict[str, Any]:
        if suppress_until is not None and suppress_until.tzinfo is None:
            raise ValueError("suppress_until must be timezone-aware")

        review = super().set_finding_state(
            finding_id,
            state,
            note=note,
            suppress_until=suppress_until,
            create_rule=False,
        )
        self._invalidate_suppression_cache()
        if not create_rule or state not in {"expected", "suppressed"}:
            return review

        row = self.connection.execute(
            "SELECT payload_json FROM findings WHERE finding_id=?",
            (finding_id,),
        ).fetchone()
        if row is None:
            return review
        finding = json.loads(str(row[0]))
        scoped_kinds = self._finding_scoped_kinds(finding_id)
        if not scoped_kinds:
            return review

        until = (
            suppress_until.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
            if suppress_until is not None
            else None
        )
        subject = str(finding.get("subject") or "")
        digest = hashlib.sha256(
            json.dumps(
                {
                    "finding_id": finding_id,
                    "subject": subject,
                    "kinds": scoped_kinds,
                    "until": until,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:16]
        rule_id = "qwr-" + digest
        created = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        with self.connection:
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
                    subject,
                    json.dumps(scoped_kinds, separators=(",", ":")),
                    until,
                    (note or state)[:500],
                    created,
                ),
            )
        self._invalidate_suppression_cache()
        return review

    def _suppression_rules(self):
        version_row = self.connection.execute("PRAGMA data_version").fetchone()
        data_version = int(version_row[0]) if version_row else 0
        if (
            self._suppression_cache is not None
            and self._suppression_cache_data_version == data_version
        ):
            return self._suppression_cache

        values = []
        rows = self.connection.execute(
            """
            SELECT source_finding_id,subject,kinds_json,expires_at
            FROM suppression_rules WHERE enabled=1
            """
        ).fetchall()
        for source_finding_id, subject, kinds_json, expires_at in rows:
            try:
                kinds = tuple(sorted(set(json.loads(str(kinds_json)))))
            except (TypeError, json.JSONDecodeError):
                kinds = ()
            if not kinds and source_finding_id:
                kinds = self._finding_scoped_kinds(str(source_finding_id))
            if not kinds:
                continue
            values.append(
                (
                    str(subject),
                    frozenset(kinds),
                    str(expires_at) if expires_at is not None else None,
                )
            )
        self._suppression_cache = tuple(values)
        self._suppression_cache_data_version = data_version
        return self._suppression_cache

    def _bypasses_suppression(self, event: SecurityEvent) -> bool:
        if event.kind in self.UNSUPPRESSIBLE_KINDS:
            return True
        return event_bypasses_suppression(event)

    def filter_suppressed_events(
        self,
        events: Iterable[SecurityEvent],
        *,
        now: datetime | None = None,
    ) -> tuple[list[SecurityEvent], list[SecurityEvent]]:
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("suppression timestamp must be timezone-aware")
        timestamp = current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        rules = self._suppression_rules()
        kept: list[SecurityEvent] = []
        suppressed: list[SecurityEvent] = []
        for event in events:
            if self._bypasses_suppression(event):
                kept.append(event)
                continue
            matched = any(
                event.subject == subject
                and event.kind.value in kinds
                and (expires_at is None or expires_at > timestamp)
                for subject, kinds, expires_at in rules
            )
            (suppressed if matched else kept).append(event)
        return kept, suppressed
