from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("baseline timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _baseline_required(name: str, required_for_resolution: bool) -> bool:
    """Long-interval external scanners are tracked but do not gate core maturity."""

    return bool(required_for_resolution and not name.startswith("scanner:"))


class CoverageBaselineTracker:
    """Small in-memory baseline projection persisted inside coverage metadata.

    Core baseline confidence reflects observation domains that can reasonably be
    re-established during normal service operation. Long-interval scanners keep
    separate maturity counters and remain fully required for resolving incidents
    sourced from those scanners; they simply do not block the entire core baseline
    from becoming established for days or weeks.
    """

    def __init__(self, initial: Mapping[str, Any] | None = None) -> None:
        self._domains: dict[str, dict[str, object]] = {}
        raw_domains = (initial or {}).get("domains") if isinstance(initial, Mapping) else None
        if isinstance(raw_domains, list):
            for raw in raw_domains:
                if not isinstance(raw, Mapping):
                    continue
                name = str(raw.get("name") or "").strip()
                if not name:
                    continue
                required_for_resolution = bool(
                    raw.get("required_for_resolution", False)
                )
                self._domains[name] = {
                    "name": name,
                    "required_for_resolution": required_for_resolution,
                    "baseline_required": bool(
                        raw.get(
                            "baseline_required",
                            _baseline_required(name, required_for_resolution),
                        )
                    ),
                    "complete_observations": max(
                        0, int(raw.get("complete_observations", 0) or 0)
                    ),
                    "degraded_observations": max(
                        0, int(raw.get("degraded_observations", 0) or 0)
                    ),
                    "scheduled_skips": max(
                        0, int(raw.get("scheduled_skips", 0) or 0)
                    ),
                    "first_complete_at": raw.get("first_complete_at"),
                    "last_complete_at": raw.get("last_complete_at"),
                    "last_state": str(raw.get("last_state") or "unknown"),
                }

    @classmethod
    def from_coverage_metadata(cls, raw: str | None) -> "CoverageBaselineTracker":
        if not raw:
            return cls()
        try:
            value = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return cls()
        if not isinstance(value, Mapping):
            return cls()
        baseline = value.get("baseline")
        return cls(baseline if isinstance(baseline, Mapping) else None)

    def observe(
        self,
        domains: Iterable[Mapping[str, Any]],
        *,
        observed_at: datetime,
    ) -> dict[str, object]:
        timestamp = _utc(observed_at)
        for raw in domains:
            name = str(raw.get("name") or "").strip()
            if not name:
                continue
            state = str(raw.get("state") or "unknown").casefold()
            required_for_resolution = bool(raw.get("required_for_resolution", False))
            item = self._domains.setdefault(
                name,
                {
                    "name": name,
                    "required_for_resolution": required_for_resolution,
                    "baseline_required": _baseline_required(
                        name,
                        required_for_resolution,
                    ),
                    "complete_observations": 0,
                    "degraded_observations": 0,
                    "scheduled_skips": 0,
                    "first_complete_at": None,
                    "last_complete_at": None,
                    "last_state": "unknown",
                },
            )
            item["required_for_resolution"] = required_for_resolution
            item["baseline_required"] = _baseline_required(
                name,
                required_for_resolution,
            )
            item["last_state"] = state
            if state == "complete":
                item["complete_observations"] = int(item["complete_observations"]) + 1
                if item["first_complete_at"] is None:
                    item["first_complete_at"] = timestamp
                item["last_complete_at"] = timestamp
            elif state == "degraded":
                item["degraded_observations"] = int(item["degraded_observations"]) + 1
            elif state == "not_due":
                item["scheduled_skips"] = int(item["scheduled_skips"]) + 1
        return self.summary()

    @staticmethod
    def _maturity(values: list[dict[str, object]]) -> tuple[bool, bool, str]:
        ready = all(
            int(item["complete_observations"]) >= 1 for item in values
        )
        established = ready and all(
            int(item["complete_observations"]) >= 3 for item in values
        )
        confidence = "established" if established else "initial" if ready else "unready"
        return ready, established, confidence

    def summary(self) -> dict[str, object]:
        values = [self._domains[name] for name in sorted(self._domains)]
        core_required = [item for item in values if item["baseline_required"]]
        scanner_domains = [
            item
            for item in values
            if str(item["name"]).startswith("scanner:")
            and item["required_for_resolution"]
        ]
        ready, established, confidence = self._maturity(core_required)
        scanner_ready, scanner_established, scanner_confidence = self._maturity(
            scanner_domains
        )
        return {
            "ready": ready,
            "established": established,
            "confidence": confidence,
            "required_domains": len(core_required),
            "core_required_domains": len(core_required),
            "scanner_domains": len(scanner_domains),
            "scanner_ready": scanner_ready if scanner_domains else True,
            "scanner_established": (
                scanner_established if scanner_domains else True
            ),
            "scanner_confidence": (
                scanner_confidence if scanner_domains else "not_configured"
            ),
            "domains": [dict(item) for item in values],
            "actions_executed": 0,
        }
