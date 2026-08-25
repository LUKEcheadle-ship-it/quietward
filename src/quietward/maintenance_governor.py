from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Any

from .cadence import CadenceController, CadenceLane
from .performance_budget import evaluate_performance_budget


OPTIONAL_DEFERRABLE_LANES = frozenset({CadenceLane.DEEP, CadenceLane.MAINTENANCE})


@dataclass(frozen=True, slots=True)
class GovernorDecision:
    performance_decision: str
    deferred_lanes: tuple[str, ...]
    protected_lanes: tuple[str, ...]
    forced_lanes: tuple[str, ...]
    max_consecutive_deferrals: int
    defer_seconds: float

    def to_dict(self) -> dict[str, object]:
        return {
            "performance_decision": self.performance_decision,
            "deferred_lanes": list(self.deferred_lanes),
            "protected_lanes": list(self.protected_lanes),
            "forced_lanes": list(self.forced_lanes),
            "max_consecutive_deferrals": self.max_consecutive_deferrals,
            "defer_seconds": self.defer_seconds,
            "actions_executed": 0,
        }


class AdaptiveMaintenanceGovernor:
    def __init__(self, *, defer_seconds: float = 60.0, max_consecutive_deferrals: int = 2) -> None:
        if defer_seconds <= 0:
            raise ValueError("defer_seconds must be positive")
        if max_consecutive_deferrals < 0:
            raise ValueError("max_consecutive_deferrals must not be negative")
        self.defer_seconds = float(defer_seconds)
        self.max_consecutive_deferrals = int(max_consecutive_deferrals)
        self._consecutive = {lane: 0 for lane in OPTIONAL_DEFERRABLE_LANES}
        self._last_decision = GovernorDecision("COLLECTING", (), (), (), self.max_consecutive_deferrals, self.defer_seconds)

    def apply(self, controller: CadenceController, metrics: Mapping[str, Any] | None, *, protected_lanes: Iterable[CadenceLane | str] = ()) -> GovernorDecision:
        budget = evaluate_performance_budget(metrics)
        performance_decision = str(budget.get("decision") or "COLLECTING")
        protected = {
            item if isinstance(item, CadenceLane) else CadenceLane(str(item))
            for item in protected_lanes
            if str(item) in {lane.value for lane in CadenceLane} or isinstance(item, CadenceLane)
        }
        forced = set(controller.forced_lanes())
        due = set(controller.decision().due_lanes)
        deferred: list[CadenceLane] = []

        if performance_decision == "PASS":
            for lane in OPTIONAL_DEFERRABLE_LANES:
                self._consecutive[lane] = 0
        elif performance_decision == "ATTENTION":
            for lane in OPTIONAL_DEFERRABLE_LANES:
                if lane not in due:
                    continue
                if lane in protected or lane in forced:
                    self._consecutive[lane] = 0
                    continue
                if self._consecutive[lane] >= self.max_consecutive_deferrals:
                    self._consecutive[lane] = 0
                    continue
                controller.defer({lane}, seconds=self.defer_seconds)
                self._consecutive[lane] += 1
                deferred.append(lane)

        self._last_decision = GovernorDecision(
            performance_decision,
            tuple(sorted(lane.value for lane in deferred)),
            tuple(sorted(lane.value for lane in protected)),
            tuple(sorted(lane.value for lane in forced)),
            self.max_consecutive_deferrals,
            self.defer_seconds,
        )
        return self._last_decision

    def note_completed(self, lanes: Iterable[CadenceLane]) -> None:
        for lane in set(lanes):
            if lane in self._consecutive:
                self._consecutive[lane] = 0

    def state(self) -> dict[str, object]:
        value = self._last_decision.to_dict()
        value["consecutive_deferrals"] = {lane.value: self._consecutive[lane] for lane in sorted(OPTIONAL_DEFERRABLE_LANES, key=lambda item: item.value)}
        value["actions_executed"] = 0
        return value
