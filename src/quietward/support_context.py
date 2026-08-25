from __future__ import annotations

import json
import sqlite3
from typing import Any


def lifecycle_context_for_finding(
    connection: sqlite3.Connection,
    finding_id: str,
) -> dict[str, Any] | None:
    """Return support-safe lifecycle context without selecting subject/host fields."""

    if not finding_id.strip():
        raise ValueError("finding_id must not be empty")
    try:
        row = connection.execute(
            """
            SELECT i.incident_key,i.signature,i.state,i.first_seen,i.last_seen,
                   i.resolved_at,i.cycles_seen,i.occurrences,i.active,
                   i.severity,i.score_band,i.event_kinds_json,
                   i.event_sources_json,t.cycle_id
            FROM incident_lifecycle_transitions t
            JOIN incident_lifecycle i ON i.incident_key=t.incident_key
            WHERE t.finding_id=?
            ORDER BY t.cycle_id DESC,t.id DESC LIMIT 1
            """,
            (finding_id,),
        ).fetchone()
        if row is None:
            row = connection.execute(
                """
                SELECT incident_key,signature,state,first_seen,last_seen,
                       resolved_at,cycles_seen,occurrences,active,severity,
                       score_band,event_kinds_json,event_sources_json,last_cycle_id
                FROM incident_lifecycle WHERE finding_id=? LIMIT 1
                """,
                (finding_id,),
            ).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    return {
        "incident_key": str(row[0]),
        "signature": str(row[1]),
        "state": str(row[2]),
        "first_seen": str(row[3]),
        "last_seen": str(row[4]),
        "resolved_at": str(row[5]) if row[5] is not None else None,
        "cycles_seen": int(row[6]),
        "occurrences": int(row[7]),
        "active": bool(row[8]),
        "severity": str(row[9]),
        "score_band": int(row[10]),
        "event_kinds": list(json.loads(str(row[11]))),
        "event_sources": list(json.loads(str(row[12]))),
        "matched_cycle_id": int(row[13]),
        "raw_subject_included": False,
        "raw_host_id_included": False,
    }
