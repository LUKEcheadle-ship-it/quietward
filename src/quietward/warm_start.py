from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping

from .cadence import CadenceLane


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


@dataclass(frozen=True, slots=True)
class WarmStartPlan:
    eligible: bool
    reason: str
    snapshot_age_seconds: float | None
    coverage_age_seconds: float | None
    evidence_valid: bool
    due_in_seconds: dict[CadenceLane, float]
    protected_lanes: tuple[CadenceLane, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "eligible": self.eligible,
            "reason": self.reason,
            "snapshot_age_seconds": round(self.snapshot_age_seconds, 3) if self.snapshot_age_seconds is not None else None,
            "coverage_age_seconds": round(self.coverage_age_seconds, 3) if self.coverage_age_seconds is not None else None,
            "evidence_valid": self.evidence_valid,
            "due_in_seconds": {lane.value: self.due_in_seconds[lane] for lane in CadenceLane},
            "protected_lanes": [lane.value for lane in self.protected_lanes],
            "actions_executed": 0,
        }


def _cold(
    reason: str,
    *,
    snapshot_age: float | None = None,
    coverage_age: float | None = None,
    evidence_valid: bool = False,
) -> WarmStartPlan:
    return WarmStartPlan(
        False,
        reason,
        snapshot_age,
        coverage_age,
        evidence_valid,
        {lane: 0.0 for lane in CadenceLane},
        (),
    )


def evaluate_warm_start(
    store,
    *,
    fast_seconds: float,
    now: datetime | None = None,
    max_snapshot_age_seconds: float = 360.0,
    max_coverage_age_seconds: float = 600.0,
) -> WarmStartPlan:
    if fast_seconds <= 0:
        raise ValueError("fast_seconds must be positive")
    if max_snapshot_age_seconds <= 0 or max_coverage_age_seconds <= 0:
        raise ValueError("warm-start freshness limits must be positive")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    try:
        snapshot = store.latest_snapshot()
    except Exception:
        return _cold("snapshot_unavailable")
    if snapshot is None:
        return _cold("no_durable_snapshot")
    observed_at = getattr(snapshot, "observed_at", None)
    if not isinstance(observed_at, datetime) or observed_at.tzinfo is None:
        return _cold("snapshot_time_invalid")
    snapshot_age = (current - observed_at.astimezone(timezone.utc)).total_seconds()
    if snapshot_age < 0 or snapshot_age > max_snapshot_age_seconds:
        return _cold("snapshot_stale", snapshot_age=snapshot_age)
    if tuple(getattr(snapshot, "errors", ()) or ()):
        return _cold("snapshot_degraded", snapshot_age=snapshot_age)

    getter = getattr(store, "get_metadata", None)
    if not callable(getter):
        return _cold("coverage_metadata_unavailable", snapshot_age=snapshot_age)
    try:
        raw_coverage = getter("last_coverage_report")
        coverage = json.loads(raw_coverage) if raw_coverage else None
    except (TypeError, json.JSONDecodeError, ValueError):
        coverage = None
    if not isinstance(coverage, Mapping):
        return _cold("coverage_metadata_invalid", snapshot_age=snapshot_age)

    coverage_time = _parse_time(coverage.get("observed_at"))
    if coverage_time is None:
        return _cold("coverage_time_invalid", snapshot_age=snapshot_age)
    coverage_age = (current - coverage_time).total_seconds()
    if coverage_age < 0 or coverage_age > max_coverage_age_seconds:
        return _cold("coverage_stale", snapshot_age=snapshot_age, coverage_age=coverage_age)

    baseline = coverage.get("baseline")
    established = (
        isinstance(baseline, Mapping)
        and bool(baseline.get("established"))
        and str(baseline.get("confidence") or "") == "established"
    )
    if not established:
        return _cold("baseline_not_established", snapshot_age=snapshot_age, coverage_age=coverage_age)
    operationally_healthy = bool(coverage.get("operationally_healthy", coverage.get("resolution_safe", False)))
    if not operationally_healthy:
        return _cold("coverage_not_healthy", snapshot_age=snapshot_age, coverage_age=coverage_age)

    try:
        evidence = store.verify_evidence_chain()
    except Exception:
        return _cold("evidence_verification_unavailable", snapshot_age=snapshot_age, coverage_age=coverage_age)
    evidence_valid = bool(evidence.get("valid", False))
    if not evidence_valid:
        return _cold("evidence_invalid", snapshot_age=snapshot_age, coverage_age=coverage_age, evidence_valid=False)

    protected_getter = getattr(store, "active_incident_lanes", None)
    try:
        protected = frozenset(protected_getter()) if callable(protected_getter) else frozenset()
    except Exception:
        return _cold("incident_state_unavailable", snapshot_age=snapshot_age, coverage_age=coverage_age, evidence_valid=True)

    phase = min(60.0, max(1.0, float(fast_seconds)))
    due = {
        CadenceLane.FAST: 0.0,
        CadenceLane.STANDARD: phase,
        CadenceLane.DEEP: phase * 2.0,
        CadenceLane.MAINTENANCE: phase * 3.0,
    }
    for lane in protected:
        if isinstance(lane, CadenceLane):
            due[lane] = 0.0

    return WarmStartPlan(
        True,
        "recent_established_verified_baseline",
        snapshot_age,
        coverage_age,
        True,
        due,
        tuple(sorted(protected, key=lambda item: item.value)),
    )
