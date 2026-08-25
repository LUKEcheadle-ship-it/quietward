from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def _table_exists(connection, name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def _suppression_active(value: object, *, now: datetime) -> bool:
    if value is None:
        return True
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return True
    if parsed.tzinfo is None:
        return True
    return parsed.astimezone(timezone.utc) > now


def current_findings(
    store,
    *,
    limit: int = 100,
    active_only: bool = False,
) -> list[dict[str, Any]]:
    bounded = max(1, min(int(limit), 1000))
    connection = getattr(store, "connection", None)
    if connection is None or not _table_exists(connection, "incident_lifecycle"):
        return store.recent_findings(bounded)

    where = "WHERE l.active=1" if active_only else ""
    rows = connection.execute(
        f"""
        SELECT f.payload_json,r.state,r.note,r.suppress_until,r.updated_at,
               l.incident_key,l.state,l.first_seen,l.last_seen,l.resolved_at,
               l.cycles_seen,l.occurrences,l.active,l.signature
        FROM incident_lifecycle l
        JOIN findings f ON f.finding_id=l.finding_id
        LEFT JOIN finding_reviews r ON r.finding_id=f.finding_id
        {where}
        ORDER BY l.active DESC,l.last_seen DESC
        LIMIT ?
        """,
        (bounded,),
    ).fetchall()
    if not rows:
        return [] if active_only else store.recent_findings(bounded)

    result: list[dict[str, Any]] = []
    for row in rows:
        finding = json.loads(str(row[0]))
        finding["review"] = {
            "state": row[1] or "open",
            "note": row[2],
            "suppress_until": row[3],
            "updated_at": row[4],
        }
        finding["incident"] = {
            "incident_key": str(row[5]),
            "state": str(row[6]),
            "first_seen": str(row[7]),
            "last_seen": str(row[8]),
            "resolved_at": str(row[9]) if row[9] is not None else None,
            "cycles_seen": int(row[10]),
            "occurrences": int(row[11]),
            "active": bool(row[12]),
            "signature": str(row[13]),
        }
        result.append(finding)
    return result


def pending_incident_alert_findings(
    store,
    *,
    severities: tuple[str, ...] = ("high", "critical"),
    limit: int = 100,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    bounded = max(1, min(int(limit), 1000))
    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    connection = getattr(store, "connection", None)
    required = {
        "incident_lifecycle",
        "incident_lifecycle_transitions",
        "alerts",
    }
    if connection is None or not all(_table_exists(connection, name) for name in required):
        return store.pending_alert_findings(severities=severities, limit=bounded)

    placeholders = ",".join("?" for _ in severities)
    rows = connection.execute(
        f"""
        SELECT f.payload_json,l.incident_key,l.state,l.signature,
               r.state,r.suppress_until,f.score,
               (
                   SELECT t.signature
                   FROM incident_lifecycle_transitions t
                   JOIN alerts a ON a.finding_id=t.finding_id
                   WHERE t.incident_key=l.incident_key
                   ORDER BY t.id DESC LIMIT 1
               ) AS last_alert_signature,
               (
                   SELECT af.score
                   FROM incident_lifecycle_transitions t
                   JOIN alerts a ON a.finding_id=t.finding_id
                   JOIN findings af ON af.finding_id=a.finding_id
                   WHERE t.incident_key=l.incident_key
                   ORDER BY t.id DESC LIMIT 1
               ) AS last_alert_score,
               (
                   SELECT t2.state
                   FROM incident_lifecycle_transitions t2
                   WHERE t2.incident_key=l.incident_key
                   ORDER BY t2.id DESC LIMIT 1 OFFSET 1
               ) AS previous_transition_state
        FROM incident_lifecycle l
        JOIN findings f ON f.finding_id=l.finding_id
        LEFT JOIN finding_reviews r ON r.finding_id=f.finding_id
        WHERE l.active=1
          AND f.severity IN ({placeholders})
        ORDER BY f.score DESC,l.last_seen DESC
        LIMIT ?
        """,
        (*severities, bounded),
    ).fetchall()

    result: list[dict[str, Any]] = []
    for row in rows:
        review_state = str(row[4] or "open")
        if review_state in {"resolved", "expected"}:
            continue
        if review_state == "suppressed" and _suppression_active(row[5], now=current_time):
            continue
        lifecycle_state = str(row[2])
        signature = str(row[3])
        current_score = float(row[6] or 0.0)
        previous_alert_signature = str(row[7]) if row[7] is not None else None
        previous_alert_score = float(row[8]) if row[8] is not None else None
        reappeared = lifecycle_state == "recurring" and str(row[9] or "") == "resolved"
        first_alert = previous_alert_signature is None
        material_non_deescalating_change = (
            lifecycle_state == "changed"
            and previous_alert_signature != signature
            and (previous_alert_score is None or current_score >= previous_alert_score)
        )
        if not (first_alert or material_non_deescalating_change or reappeared):
            continue
        finding = json.loads(str(row[0]))
        finding["incident"] = {
            "incident_key": str(row[1]),
            "state": lifecycle_state,
            "signature": signature,
            "reappeared": reappeared,
            "last_alert_score": previous_alert_score,
            "current_score": current_score,
        }
        result.append(finding)
    return result
