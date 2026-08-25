#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping


def _object(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def build_report(health: Mapping[str, Any]) -> dict[str, object]:
    performance = _object(health.get("performance")); budget = _object(health.get("performance_budget")); profiles = _object(performance.get("profiles")); fast = _object(profiles.get("fast")); context = _object(fast.get("context_metrics")); phases = _object(fast.get("phases_ms")); coverage = _object(health.get("coverage")); baseline = _object(coverage.get("baseline")); maintenance = _object(health.get("maintenance")); adaptive = _object(health.get("adaptive_maintenance")); warm_start = _object(health.get("warm_start")); temporal_context = _object(health.get("temporal_context")); health_write = _object(health.get("health_write")); cadence = _object(health.get("cadence")); latest_context = _object(performance.get("latest_context"))
    return {
        "format": "quietward-core-health-report-v1",
        "service_status": health.get("status"), "observed_at": health.get("observed_at"), "performance_budget": budget,
        "fast_profile": {"samples": fast.get("samples", 0), "total_before_health_ms": phases.get("total_before_health"), "analysis_ms": phases.get("analysis"), "collector_ms": phases.get("collector"), "process_cpu_percent_total_capacity": context.get("process_cpu_percent_total_capacity"), "rss_mib": context.get("rss_mib"), "external_commands": context.get("external_commands"), "external_command_ms": context.get("external_command_ms")},
        "latest_context": latest_context, "latest_persistence_mode": latest_context.get("persistence_mode"), "baseline": baseline,
        "coverage": {"operationally_healthy": coverage.get("operationally_healthy"), "resolution_safe": coverage.get("resolution_safe"), "degraded_required": coverage.get("degraded_required"), "scheduled_not_due": coverage.get("scheduled_not_due")},
        "cadence": cadence, "maintenance": maintenance, "adaptive_maintenance": adaptive, "warm_start": warm_start, "temporal_context": temporal_context, "health_write": health_write,
        "safety": {"actions_executed": 0, "read_only_report": True},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="read QuietWard health JSON and summarize core performance state")
    parser.add_argument("health", type=Path); parser.add_argument("--pretty", action="store_true"); args = parser.parse_args()
    raw = json.loads(args.health.read_text(encoding="utf-8"))
    if not isinstance(raw, dict): raise ValueError("health file must contain a JSON object")
    print(json.dumps(build_report(raw), indent=2 if args.pretty else None, sort_keys=True)); return 0


if __name__ == "__main__": raise SystemExit(main())
