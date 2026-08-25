from __future__ import annotations

import time
from datetime import timezone
from typing import Any

from .health_io import HealthDurabilityPolicy, atomic_live_json
from .performance_budget import evaluate_performance_budget
from .service import SentinelService, _atomic_json


class PerformanceSentinelService(SentinelService):
    """Persistent service variant with bounded-cost auxiliary state paths."""

    COVERAGE_CHECKPOINT_SECONDS = 300.0
    HEALTH_DURABLE_CHECKPOINT_SECONDS = 300.0

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._coverage_checkpoint_at: float | None = None
        self._coverage_material_state: tuple[object, ...] | None = None
        self.health_durability = HealthDurabilityPolicy(
            self.HEALTH_DURABLE_CHECKPOINT_SECONDS
        )

    @staticmethod
    def _coverage_material_key(coverage: dict[str, Any]) -> tuple[object, ...]:
        baseline = coverage.get("baseline")
        baseline_confidence = (
            str(baseline.get("confidence") or "")
            if isinstance(baseline, dict)
            else ""
        )
        degraded = []
        for raw in coverage.get("domains", []):
            if not isinstance(raw, dict):
                continue
            state = str(raw.get("state") or "")
            if state != "degraded":
                continue
            degraded.append(
                (
                    str(raw.get("name") or ""),
                    str(raw.get("reason_code") or ""),
                    int(raw.get("issue_count", 0) or 0),
                )
            )
        return (
            bool(coverage.get("operationally_healthy", coverage.get("resolution_safe", False))),
            bool(coverage.get("resolution_safe", False)),
            int(coverage.get("degraded_required", 0) or 0),
            baseline_confidence,
            tuple(sorted(degraded)),
        )

    @staticmethod
    def _health_material_key(
        *,
        status: str,
        error: object,
        consecutive_failures: int,
        performance_budget: dict[str, object],
        coverage: dict[str, Any] | None,
        lifecycle: dict[str, Any] | None,
        warm_start: dict[str, object] | None,
    ) -> tuple[object, ...]:
        coverage_value = coverage or {}
        baseline = coverage_value.get("baseline")
        baseline_confidence = (
            str(baseline.get("confidence") or "")
            if isinstance(baseline, dict)
            else ""
        )
        lifecycle_value = lifecycle or {}
        active = int(
            lifecycle_value.get(
                "active_total",
                lifecycle_value.get("active", 0),
            )
            or 0
        )
        return (
            status,
            bool(error),
            int(consecutive_failures),
            str(performance_budget.get("decision") or "COLLECTING"),
            bool(
                coverage_value.get(
                    "operationally_healthy",
                    coverage_value.get("resolution_safe", False),
                )
            ),
            bool(coverage_value.get("resolution_safe", False)),
            int(coverage_value.get("degraded_required", 0) or 0),
            baseline_confidence,
            active,
            bool((warm_start or {}).get("eligible", False)),
            str((warm_start or {}).get("reason") or ""),
        )

    def _persist_coverage_metadata(
        self,
        coverage: dict[str, Any],
        *,
        cycle_id: int,
        observed_at,
    ):
        now = time.monotonic()
        material = self._coverage_material_key(coverage)
        due = (
            self._coverage_checkpoint_at is None
            or now - self._coverage_checkpoint_at >= self.COVERAGE_CHECKPOINT_SECONDS
            or material != self._coverage_material_state
        )
        if not due:
            return (
                self._coverage_value(
                    coverage,
                    cycle_id=cycle_id,
                    observed_at=observed_at,
                    metadata_persisted=False,
                ),
                None,
            )
        value, error = super()._persist_coverage_metadata(
            coverage,
            cycle_id=cycle_id,
            observed_at=observed_at,
        )
        if error is None:
            self._coverage_checkpoint_at = now
            self._coverage_material_state = material
        return value, error

    def _write_health(
        self,
        status: str,
        *,
        result=None,
        error=None,
    ) -> None:
        health_started = time.perf_counter()
        current_result = result or self.last_result
        runtime_summary = getattr(self.store, "runtime_summary", None)
        storage = runtime_summary() if callable(runtime_summary) else self.store.summary()
        metrics = getattr(self, "runtime_metrics", None)
        metrics_summary = metrics.summary() if metrics is not None and callable(getattr(metrics, "summary", None)) else None
        performance_budget = evaluate_performance_budget(metrics_summary)
        cadence = getattr(self, "cadence_controller", None)
        cadence_state = cadence.state() if cadence is not None and callable(getattr(cadence, "state", None)) else None
        maintenance = getattr(self.store, "maintenance_state", None)
        maintenance_state = maintenance() if callable(maintenance) else None
        persistence_mode = getattr(self.store, "persistence_mode", None)
        governor = getattr(self, "adaptive_governor", None)
        governor_state = governor.state() if governor is not None and callable(getattr(governor, "state", None)) else None
        warm_start = getattr(self, "warm_start_plan", None)
        warm_start_state = warm_start.to_dict() if warm_start is not None and callable(getattr(warm_start, "to_dict", None)) else None
        contextual = getattr(self, "contextual_pipeline", None)
        temporal_state = contextual.state() if contextual is not None and callable(getattr(contextual, "state", None)) else None
        lifecycle_state = self.lifecycle_repository.summary() if self.lifecycle_repository is not None else None
        coverage_state = current_result.coverage if current_result else None
        now = time.monotonic()
        material_key = self._health_material_key(
            status=status,
            error=error,
            consecutive_failures=self.consecutive_failures,
            performance_budget=performance_budget,
            coverage=coverage_state,
            lifecycle=lifecycle_state,
            warm_start=warm_start_state,
        )
        durable_health = self.health_durability.requires_durable(
            status=status,
            persistence_mode=str(persistence_mode) if persistence_mode is not None else None,
            material_key=material_key,
            now=now,
        )
        value = {
            "service": "quietward",
            "status": status,
            "observed_at": self.clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "consecutive_failures": self.consecutive_failures,
            "last_cycle": current_result.to_dict() if current_result else None,
            "error": error,
            "storage": storage,
            "lifecycle": lifecycle_state,
            "coverage": coverage_state,
            "performance": metrics_summary,
            "performance_budget": performance_budget,
            "cadence": cadence_state,
            "maintenance": maintenance_state,
            "adaptive_maintenance": governor_state,
            "warm_start": warm_start_state,
            "temporal_context": temporal_state,
            "health_write": {
                "mode": "durable" if durable_health else "live_atomic",
                "persistence_mode": persistence_mode,
                **self.health_durability.state(now=now),
            },
            "safety": {
                "mode": "observe_only",
                "actions_executed": 0,
                "shell_used": False,
                "sudo_used": False,
                "system_state_modified": False,
                "own_state_written": True,
            },
        }
        if durable_health:
            _atomic_json(self.config.service.health_path, value)
            self.health_durability.mark_durable(material_key, now=now)
        else:
            atomic_live_json(self.config.service.health_path, value)
        amend = getattr(metrics, "amend_latest", None)
        if callable(amend) and current_result is not None:
            amend("health", (time.perf_counter() - health_started) * 1000.0)
