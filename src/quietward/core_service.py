from __future__ import annotations

from .cadence import CadenceLane
from .cadenced_service import CadencedPerformanceSentinelService
from .contextual_pipeline import ContextualPipeline
from .maintenance_governor import AdaptiveMaintenanceGovernor


class CoreSentinelService(CadencedPerformanceSentinelService):
    """Core-first policy layered on the cadence engine.

    Heavy scanners are maintenance-lane work. New/materially changed incidents
    request deeper context without making unchanged recurrence permanently
    expensive. Optional deep/maintenance work may be briefly deferred when the
    measured fast profile is over budget, but forced/incident-relevant work
    overrides the governor and starvation is bounded.

    The underlying analysis pipeline is wrapped with a bounded multi-cycle
    context window. Context is committed only after a successful observation
    cycle so undurable evidence cannot influence later findings.
    """

    def __init__(
        self,
        *args,
        adaptive_governor: AdaptiveMaintenanceGovernor | None = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._scanner_maintenance_due = True
        self.adaptive_governor = adaptive_governor or AdaptiveMaintenanceGovernor(
            defer_seconds=min(
                60.0,
                max(1.0, float(self.config.collector.interval_seconds)),
            ),
            max_consecutive_deferrals=2,
        )
        if isinstance(self.pipeline, ContextualPipeline):
            self.contextual_pipeline = self.pipeline
        else:
            self.contextual_pipeline = ContextualPipeline(self.pipeline)
            self.pipeline = self.contextual_pipeline

    def _active_incident_lanes(self) -> frozenset[CadenceLane]:
        getter = getattr(self.store, "active_incident_lanes", None)
        if not callable(getter):
            return frozenset()
        try:
            return frozenset(getter())
        except Exception:
            return frozenset({CadenceLane.DEEP, CadenceLane.MAINTENANCE})

    def _set_store_observation_scope(self, decision) -> None:
        active_domains = decision.collector_domains
        if self.cadenced_collector is not None:
            active_domains = self.cadenced_collector.set_active_domains(
                decision.collector_domains
            )
        setter = getattr(self.store, "set_cycle_observation_scope", None)
        if callable(setter):
            setter(active_domains, decision.due_lanes)

    def _safe_write_health(
        self,
        status: str,
        *,
        result=None,
        error=None,
    ) -> None:
        if (
            status == "healthy"
            and result is not None
            and hasattr(self, "contextual_pipeline")
        ):
            self.contextual_pipeline.commit_pending()
        super()._safe_write_health(status, result=result, error=error)

    def run_cycle(self):
        self.adaptive_governor.apply(
            self.cadence_controller,
            self.runtime_metrics.summary(),
            protected_lanes=self._active_incident_lanes(),
        )
        decision = self.cadence_controller.decision()
        self._set_store_observation_scope(decision)
        self._scanner_maintenance_due = decision.due(CadenceLane.MAINTENANCE)
        try:
            result = super().run_cycle()
        except Exception:
            self.contextual_pipeline.discard_pending()
            raise
        finally:
            self._scanner_maintenance_due = False

        self.contextual_pipeline.commit_pending()

        actual_lanes = {
            CadenceLane(str(item))
            for item in ((result.coverage or {}).get("cadence") or {}).get(
                "due_lanes", []
            )
            if str(item) in {lane.value for lane in CadenceLane}
        }
        self.adaptive_governor.note_completed(actual_lanes)

        lifecycle = result.lifecycle or {}
        incident_trigger = (
            int(lifecycle.get("new", 0) or 0) > 0
            or int(lifecycle.get("changed", 0) or 0) > 0
            or result.alerts_emitted > 0
        )
        if incident_trigger and CadenceLane.DEEP not in actual_lanes:
            self.cadence_controller.request(
                {
                    CadenceLane.STANDARD,
                    CadenceLane.DEEP,
                    CadenceLane.MAINTENANCE,
                }
            )
        return result

    def _scanner_due(self, scanner: str, interval_seconds: float, now) -> bool:
        if not self._scanner_maintenance_due:
            return False
        return super()._scanner_due(scanner, interval_seconds, now)
