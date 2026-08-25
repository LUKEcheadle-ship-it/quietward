from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .config import StorageSettings


@dataclass(frozen=True, slots=True)
class RetentionCapacity:
    name: str
    current: int
    limit: int

    @property
    def utilization(self) -> float:
        if self.limit <= 0:
            return 1.0
        return min(1.0, max(0.0, self.current / self.limit))

    @property
    def at_limit(self) -> bool:
        return self.current >= self.limit

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "current": self.current,
            "limit": self.limit,
            "utilization": round(self.utilization, 4),
            "at_limit": self.at_limit,
        }


@dataclass(frozen=True, slots=True)
class RetentionHealth:
    capacities: tuple[RetentionCapacity, ...]
    retention_days: int

    @property
    def caps_reached(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.capacities if item.at_limit)

    @property
    def bounded(self) -> bool:
        return self.retention_days > 0 and all(item.limit > 0 for item in self.capacities)

    def to_dict(self) -> dict[str, object]:
        return {
            "bounded": self.bounded,
            "retention_days": self.retention_days,
            "capacities": [item.to_dict() for item in self.capacities],
            "caps_reached": list(self.caps_reached),
            "actions_executed": 0,
        }


def assess_retention_health(
    settings: StorageSettings,
    summary: Mapping[str, Any],
) -> RetentionHealth:
    capacities = (
        RetentionCapacity("cycles", int(summary.get("cycles", 0) or 0), settings.max_cycles),
        RetentionCapacity("snapshots", int(summary.get("snapshots", 0) or 0), settings.max_snapshots),
        RetentionCapacity("events", int(summary.get("events", 0) or 0), settings.max_events),
        RetentionCapacity("findings", int(summary.get("findings", 0) or 0), settings.max_findings),
        RetentionCapacity("scanner_runs", int(summary.get("scanner_runs", 0) or 0), settings.max_scanner_runs),
    )
    return RetentionHealth(capacities, settings.retention_days)
