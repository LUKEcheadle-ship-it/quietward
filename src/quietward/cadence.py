from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable, Iterable, Mapping

from .coverage import CoverageDomain, CoverageState, not_due_domain


class CadenceLane(StrEnum):
    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"
    MAINTENANCE = "maintenance"


COLLECTOR_DOMAIN_LANES: dict[str, CadenceLane] = {
    "processes": CadenceLane.FAST,
    "listening_sockets": CadenceLane.FAST,
    "outbound_connections": CadenceLane.FAST,
    "authentication": CadenceLane.FAST,
    "persistence": CadenceLane.STANDARD,
    "docker": CadenceLane.STANDARD,
    "sensitive_files": CadenceLane.DEEP,
}


@dataclass(frozen=True, slots=True)
class CadenceDecision:
    due_lanes: tuple[CadenceLane, ...]
    collector_domains: frozenset[str]
    first_cycle: bool

    def due(self, lane: CadenceLane) -> bool:
        return lane in self.due_lanes

    def to_dict(self) -> dict[str, object]:
        return {
            "due_lanes": [lane.value for lane in self.due_lanes],
            "collector_domains": sorted(self.collector_domains),
            "first_cycle": self.first_cycle,
            "actions_executed": 0,
        }


class CadenceController:
    """In-memory lane scheduler for one persistent QuietWard process.

    Cold starts make every lane due. A separately verified recent baseline may
    restore a staged warm-start schedule so fast observation resumes immediately
    while heavier lanes are revalidated over the next few fast intervals.

    Optional lanes may also be deferred for a short bounded period by the core
    performance governor. A forced security request always overrides deferral.
    """

    def __init__(
        self,
        *,
        fast_seconds: float,
        standard_seconds: float = 300.0,
        deep_seconds: float = 900.0,
        maintenance_seconds: float = 300.0,
        phase_offsets_seconds: Mapping[CadenceLane, float] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        values = {
            CadenceLane.FAST: float(fast_seconds),
            CadenceLane.STANDARD: float(standard_seconds),
            CadenceLane.DEEP: float(deep_seconds),
            CadenceLane.MAINTENANCE: float(maintenance_seconds),
        }
        if any(value <= 0 for value in values.values()):
            raise ValueError("cadence intervals must be positive")
        if values[CadenceLane.STANDARD] < values[CadenceLane.FAST]:
            raise ValueError("standard cadence must not be faster than fast cadence")
        if values[CadenceLane.DEEP] < values[CadenceLane.STANDARD]:
            raise ValueError("deep cadence must not be faster than standard cadence")
        raw_offsets = dict(phase_offsets_seconds or {})
        offsets = {
            lane: float(raw_offsets.get(lane, 0.0)) for lane in CadenceLane
        }
        if any(value < 0 for value in offsets.values()):
            raise ValueError("cadence phase offsets must not be negative")
        self.intervals = values
        self.phase_offsets = offsets
        self._monotonic = monotonic
        self._last_completed: dict[CadenceLane, float] = {}
        self._next_due: dict[CadenceLane, float] = {}
        self._forced_due: set[CadenceLane] = set()
        self._deferred_until: dict[CadenceLane, float] = {}
        self._restored_schedule = False

    def request(self, lanes: Iterable[CadenceLane]) -> None:
        self._forced_due.update(set(lanes))

    def forced_lanes(self) -> frozenset[CadenceLane]:
        return frozenset(self._forced_due)

    def restore_due_schedule(
        self,
        due_in_seconds: Mapping[CadenceLane, float],
    ) -> None:
        """Restore process-local cadence from an externally verified baseline.

        This method does not validate persistence/evidence freshness itself. The
        caller must only use it after a warm-start safety check. Every lane must
        be present so a partial restore cannot accidentally hide work.
        """

        missing = set(CadenceLane) - set(due_in_seconds)
        if missing:
            raise ValueError(
                "warm-start cadence must specify every lane: "
                + ",".join(sorted(lane.value for lane in missing))
            )
        values = {lane: float(due_in_seconds[lane]) for lane in CadenceLane}
        if any(value < 0 for value in values.values()):
            raise ValueError("warm-start due times must not be negative")
        now = self._monotonic()
        self._last_completed = {lane: now for lane in CadenceLane}
        self._next_due = {lane: now + values[lane] for lane in CadenceLane}
        self._forced_due.clear()
        self._deferred_until.clear()
        self._restored_schedule = True

    def defer(self, lanes: Iterable[CadenceLane], *, seconds: float) -> None:
        """Temporarily postpone optional lanes without changing their base cadence.

        FAST is never deferrable. Forced lanes remain immediately due. Repeated
        deferrals extend only to the latest requested release time; starvation
        prevention is owned by the caller/governor.
        """

        delay = float(seconds)
        if delay <= 0:
            raise ValueError("cadence deferral seconds must be positive")
        now = self._monotonic()
        for lane in set(lanes):
            if lane == CadenceLane.FAST:
                raise ValueError("fast cadence cannot be deferred")
            if lane in self._forced_due:
                continue
            release = now + delay
            self._deferred_until[lane] = max(
                release,
                self._deferred_until.get(lane, 0.0),
            )

    def decision(self) -> CadenceDecision:
        now = self._monotonic()
        first = not self._last_completed
        due: list[CadenceLane] = []
        for lane in CadenceLane:
            next_due = self._next_due.get(lane)
            forced = lane in self._forced_due
            deferred_until = self._deferred_until.get(lane)
            deferred = (
                not forced
                and deferred_until is not None
                and now < deferred_until
            )
            if deferred:
                continue
            if forced or next_due is None or now >= next_due:
                due.append(lane)
        domains = {
            name
            for name, lane in COLLECTOR_DOMAIN_LANES.items()
            if lane in due
        }
        return CadenceDecision(tuple(due), frozenset(domains), first)

    def mark_completed(self, lanes: Iterable[CadenceLane]) -> None:
        now = self._monotonic()
        completed = set(lanes)
        for lane in completed:
            first_completion = lane not in self._last_completed
            self._last_completed[lane] = now
            self._next_due[lane] = (
                now
                + self.intervals[lane]
                + (self.phase_offsets[lane] if first_completion else 0.0)
            )
            self._deferred_until.pop(lane, None)
        self._forced_due.difference_update(completed)

    def state(self) -> dict[str, object]:
        now = self._monotonic()
        return {
            "interval_seconds": {
                lane.value: self.intervals[lane] for lane in CadenceLane
            },
            "phase_offset_seconds": {
                lane.value: self.phase_offsets[lane] for lane in CadenceLane
            },
            "seconds_since_completed": {
                lane.value: (
                    round(max(0.0, now - self._last_completed[lane]), 3)
                    if lane in self._last_completed
                    else None
                )
                for lane in CadenceLane
            },
            "seconds_until_due": {
                lane.value: (
                    round(max(0.0, self._next_due[lane] - now), 3)
                    if lane in self._next_due
                    else 0.0
                )
                for lane in CadenceLane
            },
            "seconds_until_deferral_release": {
                lane.value: (
                    round(max(0.0, self._deferred_until[lane] - now), 3)
                    if lane in self._deferred_until
                    and self._deferred_until[lane] > now
                    else 0.0
                )
                for lane in CadenceLane
            },
            "forced_due": sorted(lane.value for lane in self._forced_due),
            "restored_schedule": self._restored_schedule,
            "actions_executed": 0,
        }


def apply_collector_cadence(
    domains: Iterable[CoverageDomain],
    active_domains: Iterable[str],
) -> tuple[CoverageDomain, ...]:
    """Mark enabled collector domains skipped by cadence as explicitly not due."""

    active = set(active_domains)
    result: list[CoverageDomain] = []
    for value in domains:
        if (
            value.name in COLLECTOR_DOMAIN_LANES
            and value.name not in active
            and value.state == CoverageState.COMPLETE
        ):
            result.append(not_due_domain(value.name))
        else:
            result.append(value)
    return tuple(result)


def operationally_healthy(domains: Iterable[CoverageDomain]) -> bool:
    """Scheduled not-due work is healthy; required degraded work is not."""

    return all(
        not value.required_for_resolution
        or value.state in {CoverageState.COMPLETE, CoverageState.NOT_DUE}
        for value in domains
    )


def cadence_counts(domains: Iterable[CoverageDomain]) -> dict[str, int]:
    values = tuple(domains)
    return {
        "scheduled_not_due": sum(
            value.state == CoverageState.NOT_DUE for value in values
        ),
        "degraded_required": sum(
            value.required_for_resolution and value.state == CoverageState.DEGRADED
            for value in values
        ),
    }
