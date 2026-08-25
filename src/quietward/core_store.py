from __future__ import annotations

import json
from typing import Iterable

from .cadence import COLLECTOR_DOMAIN_LANES, CadenceLane
from .incident_coverage import SCANNER_SOURCES, _collector_domain
from .maintenance_store import MaintenanceSentinelStore


class CoreSentinelStore(MaintenanceSentinelStore):
    """Maintenance store aware of the current observation scope."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cycle_domains: frozenset[str] = frozenset()
        self._cycle_lanes: frozenset[str] = frozenset()

    def set_cycle_observation_scope(
        self,
        domains: Iterable[str],
        lanes: Iterable[CadenceLane | str],
    ) -> None:
        self._cycle_domains = frozenset(str(item) for item in domains)
        self._cycle_lanes = frozenset(
            item.value if isinstance(item, CadenceLane) else str(item)
            for item in lanes
        )

    def _active_incident_sources(self) -> tuple[tuple[str, ...], ...]:
        table = self.connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type='table' AND name='incident_lifecycle'
            """
        ).fetchone()
        if table is None:
            return ()
        rows = self.connection.execute(
            "SELECT event_sources_json FROM incident_lifecycle WHERE active=1"
        ).fetchall()
        result: list[tuple[str, ...]] = []
        for row in rows:
            try:
                sources = tuple(
                    str(item).casefold().strip()
                    for item in json.loads(str(row[0]))
                    if str(item).strip()
                )
            except (json.JSONDecodeError, TypeError):
                result.append(("__unknown__",))
                continue
            result.append(sources or ("__unknown__",))
        return tuple(result)

    def active_incident_lanes(self) -> frozenset[CadenceLane]:
        lanes: set[CadenceLane] = set()
        for sources in self._active_incident_sources():
            for source in sources:
                if source == "__unknown__":
                    lanes.update(
                        {
                            CadenceLane.FAST,
                            CadenceLane.STANDARD,
                            CadenceLane.DEEP,
                            CadenceLane.MAINTENANCE,
                        }
                    )
                    continue
                if source in SCANNER_SOURCES:
                    lanes.add(CadenceLane.MAINTENANCE)
                    continue
                mapped = _collector_domain(source)
                if mapped is None or mapped == "evidence_chain":
                    lanes.update({CadenceLane.DEEP, CadenceLane.MAINTENANCE})
                    continue
                if mapped == "self_integrity":
                    lanes.add(CadenceLane.DEEP)
                    continue
                if mapped == "microsoft_defender":
                    lanes.add(CadenceLane.FAST)
                    continue
                lane = COLLECTOR_DOMAIN_LANES.get(mapped)
                if lane is not None:
                    lanes.add(lane)
        return frozenset(lanes)

    def _active_incidents_require_durable_cycle(self) -> bool:
        for sources in self._active_incident_sources():
            for source in sources:
                if source == "__unknown__":
                    return True
                if source in SCANNER_SOURCES:
                    if CadenceLane.MAINTENANCE.value in self._cycle_lanes:
                        return True
                    continue
                mapped = _collector_domain(source)
                if mapped is None:
                    return True
                if mapped == "self_integrity":
                    if CadenceLane.DEEP.value in self._cycle_lanes:
                        return True
                    continue
                if mapped == "evidence_chain":
                    return True
                if mapped == "microsoft_defender":
                    if "processes" in self._cycle_domains:
                        return True
                    continue
                if mapped in self._cycle_domains:
                    return True
        return False

    def _active_incident_count(self) -> int:
        actual = super()._active_incident_count()
        if actual == 0:
            return 0
        return actual if self._active_incidents_require_durable_cycle() else 0

    def maintenance_state(self) -> dict[str, object]:
        value = dict(super().maintenance_state())
        value["cycle_observation_domains"] = sorted(self._cycle_domains)
        value["cycle_due_lanes"] = sorted(self._cycle_lanes)
        value["active_incident_lanes"] = sorted(
            lane.value for lane in self.active_incident_lanes()
        )
        value["actions_executed"] = 0
        return value
