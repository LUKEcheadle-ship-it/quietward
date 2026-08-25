from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .enhanced_dashboard import QuietWardDashboardServer
from .lifecycle_repository import IncidentLifecycleRepository
from .operational_findings import current_findings
from .retention_health import assess_retention_health
from .storage import SentinelStore


_INSTALLED = False
_ORIGINAL_HTML = QuietWardDashboardServer._html


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _cache_matches_chain_head(
    store: SentinelStore,
    value: dict[str, Any],
) -> bool:
    count = int(store.connection.execute("SELECT COUNT(*) FROM evidence_chain").fetchone()[0])
    try:
        cached_count = int(value.get("cycles_checked", -1))
    except (TypeError, ValueError):
        return False
    if cached_count != count:
        return False
    if count == 0:
        return value.get("last_chain_hash") in {None, ""}
    row = store.connection.execute(
        "SELECT chain_hash FROM evidence_chain ORDER BY cycle_id DESC LIMIT 1"
    ).fetchone()
    return row is not None and str(row[0]) == str(value.get("last_chain_hash") or "")


def cached_evidence_status(
    store: SentinelStore,
    *,
    max_age_seconds: float = 600.0,
    now: datetime | None = None,
) -> dict[str, Any]:
    if max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be positive")
    raw = store.get_metadata("last_evidence_verification_report")
    if raw:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            value = None
        if isinstance(value, dict):
            observed = _parse_time(value.get("observed_at"))
            current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
            if (
                observed is not None
                and 0.0 <= (current - observed).total_seconds() <= max_age_seconds
                and isinstance(value.get("valid"), bool)
                and _cache_matches_chain_head(store, value)
            ):
                safe = dict(value)
                safe["cached_for_dashboard"] = True
                safe["errors"] = []
                safe["actions_executed"] = 0
                return safe

    value = dict(store.verify_evidence_chain())
    value["cached_for_dashboard"] = False
    value["actions_executed"] = 0
    return value


def fast_storage_summary(store: SentinelStore) -> dict[str, Any]:
    connection = store.connection

    def count(table: str) -> int:
        return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    states = {
        str(row[0]): int(row[1])
        for row in connection.execute(
            "SELECT state,COUNT(*) FROM finding_reviews GROUP BY state"
        )
    }
    last = connection.execute(
        """
        SELECT completed_at,status,events_count,findings_count,
               actions_executed,error
        FROM cycles ORDER BY id DESC LIMIT 1
        """
    ).fetchone()
    return {
        "schema_version": store.SCHEMA_VERSION,
        "cycles": count("cycles"),
        "snapshots": count("snapshots"),
        "events": count("events"),
        "findings": count("findings"),
        "proposals": count("proposals"),
        "alerts": count("alerts"),
        "scanner_runs": count("scanner_runs"),
        "suppression_rules": count("suppression_rules"),
        "evidence_signatures": count("evidence_signatures"),
        "finding_states": states,
        "evidence_chain": cached_evidence_status(store),
        "last_cycle": dict(last) if last else None,
        "actions_executed": 0,
    }


def fast_overview(store: SentinelStore, limit: int) -> dict[str, Any]:
    snapshot = store.latest_snapshot()
    collector = None
    collector_errors: list[str] = []
    if snapshot is not None:
        collector = {
            "version": snapshot.collector_version,
            "observed_at": snapshot.to_dict()["observed_at"],
            "microsoft_defender": snapshot.defender.to_dict() if snapshot.defender else None,
        }
        collector_errors = list(snapshot.errors)

    findings = current_findings(store, limit=limit, active_only=True)
    severities: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "info")
        severities[severity] = severities.get(severity, 0) + 1

    summary = fast_storage_summary(store)
    summary["historical_findings"] = summary["findings"]
    summary["operational_findings"] = len(findings)
    summary["findings_by_severity"] = severities
    lifecycle = IncidentLifecycleRepository(store.connection)
    return {
        "summary": summary,
        "findings": findings,
        "events": store.recent_events(min(limit, 100)),
        "collector": collector,
        "collector_errors": collector_errors,
        "actions_executed": 0,
        "mode": "observe_only",
        "lifecycle": lifecycle.summary(),
        "incidents": lifecycle.recent_incidents(limit=limit, active_only=True),
        "lifecycle_transitions": lifecycle.recent_transitions(min(limit, 100)),
        "coverage": QuietWardDashboardServer._coverage(store),
        "retention": assess_retention_health(store.settings, summary).to_dict(),
        "product": "QuietWard",
        "dashboard_mode": "read_only",
    }


def _performance_html() -> str:
    return (
        _ORIGINAL_HTML()
        .replace("/api/overview?limit=200", "/api/overview?limit=100")
        .replace("setInterval(refresh,15000)", "setInterval(refresh,60000)")
        .replace(
            "const safe=cov&&cov.resolution_safe===true",
            "const safe=cov&&(cov.operationally_healthy??cov.resolution_safe)===true",
        )
    )


def install_dashboard_performance() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    QuietWardDashboardServer._overview = staticmethod(fast_overview)
    QuietWardDashboardServer._html = staticmethod(_performance_html)
    _INSTALLED = True
