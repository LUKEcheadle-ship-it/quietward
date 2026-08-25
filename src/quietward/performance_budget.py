from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class PerformanceTargets:
    idle_cpu_percent_total_capacity: float = 2.0
    rss_mib: float = 100.0
    fast_p50_ms: float = 500.0
    fast_p95_ms: float = 1500.0
    analysis_p95_ms: float = 50.0
    min_fast_samples: int = 5


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def evaluate_performance_budget(
    metrics: Mapping[str, Any] | None,
    *,
    targets: PerformanceTargets | None = None,
) -> dict[str, object]:
    target = targets or PerformanceTargets()
    profiles = metrics.get("profiles") if isinstance(metrics, Mapping) else None
    fast = profiles.get("fast") if isinstance(profiles, Mapping) else None
    if not isinstance(fast, Mapping):
        return {
            "decision": "COLLECTING",
            "fast_samples": 0,
            "minimum_fast_samples": target.min_fast_samples,
            "checks": [],
            "actions_executed": 0,
        }

    samples = int(fast.get("samples", 0) or 0)
    phases = fast.get("phases_ms") if isinstance(fast.get("phases_ms"), Mapping) else {}
    context = fast.get("context_metrics") if isinstance(fast.get("context_metrics"), Mapping) else {}

    def phase(metric: str, statistic: str) -> float | None:
        value = phases.get(metric)
        return _number(value.get(statistic)) if isinstance(value, Mapping) else None

    def context_metric(metric: str, statistic: str) -> float | None:
        value = context.get(metric)
        return _number(value.get(statistic)) if isinstance(value, Mapping) else None

    checks: list[dict[str, object]] = []

    def check(name: str, observed: float | None, maximum: float, unit: str) -> None:
        checks.append(
            {
                "name": name,
                "observed": round(observed, 3) if observed is not None else None,
                "maximum": maximum,
                "unit": unit,
                "pass": observed is not None and observed <= maximum,
            }
        )

    check("idle_cpu_mean", context_metric("process_cpu_percent_total_capacity", "mean"), target.idle_cpu_percent_total_capacity, "percent_total_capacity")
    check("rss_max", context_metric("rss_mib", "max"), target.rss_mib, "MiB")
    check("fast_cycle_p50", phase("total_before_health", "p50"), target.fast_p50_ms, "ms")
    check("fast_cycle_p95", phase("total_before_health", "p95"), target.fast_p95_ms, "ms")
    check("analysis_p95", phase("analysis", "p95"), target.analysis_p95_ms, "ms")

    if samples < target.min_fast_samples:
        decision = "COLLECTING"
    elif all(bool(item["pass"]) for item in checks):
        decision = "PASS"
    else:
        decision = "ATTENTION"

    return {
        "decision": decision,
        "fast_samples": samples,
        "minimum_fast_samples": target.min_fast_samples,
        "checks": checks,
        "actions_executed": 0,
    }
