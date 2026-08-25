from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Iterable, Mapping


class LifecycleState(StrEnum):
    NEW = "new"
    RECURRING = "recurring"
    CHANGED = "changed"
    RESOLVED = "resolved"


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("lifecycle timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _score_band(value: object) -> int:
    try:
        score = max(0.0, min(100.0, float(value)))
    except (TypeError, ValueError):
        score = 0.0
    return int(score // 10.0) * 10


def _stable_hash(prefix: str, value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return prefix + hashlib.sha256(payload).hexdigest()[:24]


@dataclass(frozen=True, slots=True)
class IncidentIdentity:
    incident_key: str
    signature: str
    finding_id: str
    host_id: str
    subject: str
    severity: str
    score_band: int
    event_kinds: tuple[str, ...]
    event_sources: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "incident_key": self.incident_key,
            "signature": self.signature,
            "finding_id": self.finding_id,
            "host_id": self.host_id,
            "subject": self.subject,
            "severity": self.severity,
            "score_band": self.score_band,
            "event_kinds": list(self.event_kinds),
            "event_sources": list(self.event_sources),
        }


@dataclass(frozen=True, slots=True)
class LifecycleRecord:
    identity: IncidentIdentity
    state: LifecycleState
    first_seen: datetime
    last_seen: datetime
    resolved_at: datetime | None
    cycles_seen: int
    occurrences: int
    active: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "first_seen": _utc(self.first_seen),
            "last_seen": _utc(self.last_seen),
            "resolved_at": _utc(self.resolved_at) if self.resolved_at else None,
            "cycles_seen": self.cycles_seen,
            "occurrences": self.occurrences,
            "active": self.active,
            "incident": self.identity.to_dict(),
        }


def build_incident_identity(
    finding: Mapping[str, Any],
    events: Iterable[Mapping[str, Any]],
) -> IncidentIdentity:
    finding_id = str(finding.get("finding_id") or "").strip()
    host_id = str(finding.get("host_id") or "").strip()
    subject = str(finding.get("subject") or "").strip()
    severity = str(finding.get("severity") or "info").strip().casefold()
    if not finding_id:
        raise ValueError("finding_id must not be empty")
    if not host_id:
        raise ValueError("host_id must not be empty")
    if not subject:
        raise ValueError("subject must not be empty")

    evidence_ids = {
        str(value)
        for value in finding.get("evidence_event_ids", ())
        if str(value).strip()
    }
    kinds: set[str] = set()
    sources: set[str] = set()
    for event in events:
        event_id = str(event.get("event_id") or "")
        if evidence_ids and event_id not in evidence_ids:
            continue
        kind = str(event.get("kind") or "").strip().casefold()
        source = str(event.get("source") or "").strip().casefold()
        if kind:
            kinds.add(kind)
        if source:
            sources.add(source)

    score_band = _score_band(finding.get("score"))
    event_kinds = tuple(sorted(kinds))
    event_sources = tuple(sorted(sources))
    incident_key = _stable_hash(
        "qwi-",
        {"version": 1, "host_id": host_id, "subject": subject},
    )
    signature = _stable_hash(
        "qws-",
        {
            "version": 1,
            "severity": severity,
            "score_band": score_band,
            "event_kinds": event_kinds,
            "event_sources": event_sources,
        },
    )
    return IncidentIdentity(
        incident_key=incident_key,
        signature=signature,
        finding_id=finding_id,
        host_id=host_id,
        subject=subject,
        severity=severity,
        score_band=score_band,
        event_kinds=event_kinds,
        event_sources=event_sources,
    )


def observe_incident(
    previous: LifecycleRecord | None,
    identity: IncidentIdentity,
    *,
    observed_at: datetime,
) -> LifecycleRecord:
    _utc(observed_at)
    if previous is None:
        return LifecycleRecord(
            identity=identity,
            state=LifecycleState.NEW,
            first_seen=observed_at,
            last_seen=observed_at,
            resolved_at=None,
            cycles_seen=1,
            occurrences=1,
            active=True,
        )
    if previous.identity.incident_key != identity.incident_key:
        raise ValueError("incident identity does not match lifecycle record")

    if not previous.active or previous.state == LifecycleState.RESOLVED:
        state = LifecycleState.RECURRING
    elif previous.identity.signature != identity.signature:
        state = LifecycleState.CHANGED
    else:
        state = LifecycleState.RECURRING

    occurrence_delta = int(previous.identity.finding_id != identity.finding_id)
    return LifecycleRecord(
        identity=identity,
        state=state,
        first_seen=previous.first_seen,
        last_seen=observed_at,
        resolved_at=None,
        cycles_seen=previous.cycles_seen + 1,
        occurrences=previous.occurrences + occurrence_delta,
        active=True,
    )


def resolve_absent_incidents(
    records: Mapping[str, LifecycleRecord],
    seen_incident_keys: Iterable[str],
    *,
    completed_at: datetime,
    coverage_complete: bool,
) -> dict[str, LifecycleRecord]:
    _utc(completed_at)
    seen = set(seen_incident_keys)
    result = dict(records)
    if not coverage_complete:
        return result
    for incident_key, record in records.items():
        if incident_key in seen or not record.active:
            continue
        result[incident_key] = replace(
            record,
            state=LifecycleState.RESOLVED,
            resolved_at=completed_at,
            active=False,
        )
    return result
