from __future__ import annotations

import statistics
from collections import deque
from dataclasses import dataclass
from typing import Mapping


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))
    return ordered[index]


def _stats(values: list[float]) -> dict[str, float]:
    return {
        "mean": round(statistics.fmean(values), 3) if values else 0.0,
        "p50": round(_percentile(values, 0.50), 3),
        "p95": round(_percentile(values, 0.95), 3),
        "max": round(max(values), 3) if values else 0.0,
    }


def _profile_name(context: Mapping[str, object]) -> str:
    raw = context.get("due_lanes")
    if not isinstance(raw, (list, tuple)):
        return "unknown"
    lanes = [str(item).strip() for item in raw if str(item).strip()]
    return "+".join(lanes) if lanes else "unknown"


def _numeric_context(samples: list["RuntimeSample"]) -> dict[str, dict[str, float]]:
    names = sorted({name for sample in samples for name, value in sample.context.items() if not isinstance(value, bool) and isinstance(value, (int, float))})
    result: dict[str, dict[str, float]] = {}
    for name in names:
        values = [float(sample.context[name]) for sample in samples if name in sample.context and not isinstance(sample.context[name], bool) and isinstance(sample.context[name], (int, float))]
        result[name] = _stats(values)
    return result


def _phase_summary(samples: list["RuntimeSample"]) -> dict[str, dict[str, float]]:
    phase_names = sorted({name for sample in samples for name in sample.phases_ms})
    phases: dict[str, dict[str, float]] = {}
    for name in phase_names:
        values = [sample.phases_ms[name] for sample in samples if name in sample.phases_ms]
        phases[name] = _stats(values)
    return phases


@dataclass(frozen=True, slots=True)
class RuntimeSample:
    phases_ms: dict[str, float]
    context: dict[str, object]


class RuntimeMetrics:
    def __init__(self, max_samples: int = 120) -> None:
        if max_samples <= 0:
            raise ValueError("max_samples must be positive")
        self.max_samples = int(max_samples)
        self._samples: deque[RuntimeSample] = deque(maxlen=self.max_samples)

    def record(self, phases_ms: Mapping[str, float], *, context: Mapping[str, object] | None = None) -> None:
        clean: dict[str, float] = {}
        for name, value in phases_ms.items():
            clean[str(name)] = round(max(0.0, float(value)), 3)
        self._samples.append(RuntimeSample(clean, dict(context or {})))

    def amend_latest(self, name: str, value_ms: float) -> None:
        if not self._samples:
            return
        latest = self._samples.pop()
        phases = dict(latest.phases_ms)
        phases[str(name)] = round(max(0.0, float(value_ms)), 3)
        self._samples.append(RuntimeSample(phases, latest.context))

    def summary(self) -> dict[str, object]:
        samples = list(self._samples)
        latest = samples[-1] if samples else None
        profile_names = sorted({_profile_name(sample.context) for sample in samples})
        profiles: dict[str, object] = {}
        for profile_name in profile_names:
            profile_samples = [sample for sample in samples if _profile_name(sample.context) == profile_name]
            profiles[profile_name] = {
                "samples": len(profile_samples),
                "phases_ms": _phase_summary(profile_samples),
                "context_metrics": _numeric_context(profile_samples),
                "latest_context": dict(profile_samples[-1].context) if profile_samples else {},
            }
        return {
            "samples": len(samples),
            "capacity": self.max_samples,
            "phases_ms": _phase_summary(samples),
            "context_metrics": _numeric_context(samples),
            "profiles": profiles,
            "latest_ms": dict(latest.phases_ms) if latest else {},
            "latest_context": dict(latest.context) if latest else {},
            "actions_executed": 0,
        }
