from __future__ import annotations

import os
import time
from typing import Any

from .baseline import CoverageBaselineTracker
from .cadence import (
    CadenceController,
    CadenceLane,
    apply_collector_cadence,
    cadence_counts,
    operationally_healthy,
)
from .cadenced_collector import CadencedCollectorAdapter
from .collectors import CollectionBatch
from .contracts import SecurityEvent
from .coverage import (
    collector_coverage,
    complete_domain,
    degraded_domain,
    domain,
    not_due_domain,
    report as coverage_report,
)
from .freshness import ScannerFreshnessInspector
from .performance_service import PerformanceSentinelService
from .process_metrics import process_resource_snapshot
from .runtime_metrics import RuntimeMetrics
from .service import ServiceCycleResult


class CadencedPerformanceSentinelService(PerformanceSentinelService):
    """Persistent service with explicit fast/standard/deep/maintenance cadence."""

    def __init__(
        self,
        *args,
        cadence_controller: CadenceController | None = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.cadence_controller = cadence_controller or CadenceController(
            fast_seconds=self.config.collector.interval_seconds,
            standard_seconds=max(300.0, self.config.collector.interval_seconds),
            deep_seconds=max(900.0, self.config.collector.interval_seconds),
            maintenance_seconds=max(300.0, self.config.collector.interval_seconds),
        )
        self.runtime_metrics = RuntimeMetrics(max_samples=120)
        self._resource_wall_at = time.monotonic()
        self._resource_cpu_at = time.process_time()
        raw_coverage = None
        get_metadata = getattr(self.store, "get_metadata", None)
        if callable(get_metadata):
            try:
                raw_coverage = get_metadata("last_coverage_report")
            except Exception:
                raw_coverage = None
        self.baseline_tracker = CoverageBaselineTracker.from_coverage_metadata(raw_coverage)
        self.cadenced_collector: CadencedCollectorAdapter | None = None
        try:
            self.cadenced_collector = CadencedCollectorAdapter(self.collector)
            self.collector = self.cadenced_collector
        except TypeError:
            self.cadenced_collector = None

    def _command_snapshot(self) -> dict[str, float]:
        runner = getattr(self.collector, "runner", None)
        snapshot = getattr(runner, "performance_snapshot", None)
        if not callable(snapshot):
            return {"commands_executed": 0.0, "command_duration_ms": 0.0}
        try:
            value = snapshot()
            return {
                "commands_executed": float(value.get("commands_executed", 0) or 0),
                "command_duration_ms": float(value.get("command_duration_ms", 0) or 0),
            }
        except (TypeError, ValueError):
            return {"commands_executed": 0.0, "command_duration_ms": 0.0}

    @staticmethod
    def _elapsed_ms(started: float) -> float:
        return (time.perf_counter() - started) * 1000.0

    def _resource_context(self) -> dict[str, object]:
        wall_now = time.monotonic()
        cpu_now = time.process_time()
        wall_elapsed = max(0.0, wall_now - self._resource_wall_at)
        cpu_elapsed = max(0.0, cpu_now - self._resource_cpu_at)
        self._resource_wall_at = wall_now
        self._resource_cpu_at = cpu_now

        values: dict[str, object] = {}
        cpu_count = max(1, int(os.cpu_count() or 1))
        if wall_elapsed > 0.0:
            values["process_cpu_percent_total_capacity"] = round(
                (cpu_elapsed / wall_elapsed) * 100.0 / cpu_count,
                4,
            )
        resource = process_resource_snapshot()
        rss_mib = resource.get("rss_mib")
        if isinstance(rss_mib, (int, float)) and not isinstance(rss_mib, bool):
            values["rss_mib"] = float(rss_mib)
        persistence_mode = getattr(self.store, "persistence_mode", None)
        if isinstance(persistence_mode, str) and persistence_mode:
            values["persistence_mode"] = persistence_mode
        return values

    def run_cycle(self) -> ServiceCycleResult:
        cycle_perf = time.perf_counter()
        phases: dict[str, float] = {}
        decision = self.cadence_controller.decision()
        if self.cadenced_collector is not None:
            active_domains = self.cadenced_collector.set_active_domains(
                decision.collector_domains
            )
        else:
            active_domains = frozenset(
                {
                    "processes",
                    "listening_sockets",
                    "outbound_connections",
                    "authentication",
                    "docker",
                    "persistence",
                    "sensitive_files",
                }
            )

        started = self.clock()
        phase = time.perf_counter()
        previous = self.store.latest_snapshot()
        phases["snapshot_load"] = self._elapsed_ms(phase)

        command_before = self._command_snapshot()
        phase = time.perf_counter()
        collector_batch = self.collector.collect(previous)
        phases["collector"] = self._elapsed_ms(phase)
        command_after = self._command_snapshot()

        extra_events: list[SecurityEvent] = []
        errors = list(collector_batch.snapshot.errors)
        coverage_domains = list(
            apply_collector_cadence(
                collector_coverage(
                    self.config.collector,
                    collector_batch.snapshot.errors,
                    collector_version=collector_batch.snapshot.collector_version,
                ),
                active_domains,
            )
        )

        phase = time.perf_counter()
        chain = self.store.verify_evidence_chain()
        phases["evidence"] = self._elapsed_ms(phase)
        if chain["cycles_checked"] and not chain["valid"]:
            extra_events.append(self._evidence_failure_event(chain, started))
            coverage_domains.append(
                degraded_domain(
                    "evidence_chain",
                    reason_code="evidence_integrity_invalid",
                )
            )
        else:
            coverage_domains.append(complete_domain("evidence_chain"))

        phase = time.perf_counter()
        integrity_events: list[SecurityEvent] = []
        integrity_manifest = None
        if not self.config.self_integrity.enabled:
            coverage_domains.append(domain("self_integrity", enabled=False))
        elif self.integrity_monitor is None:
            coverage_domains.append(
                degraded_domain(
                    "self_integrity",
                    reason_code="monitor_unavailable",
                )
            )
        elif not decision.due(CadenceLane.DEEP):
            coverage_domains.append(not_due_domain("self_integrity"))
        else:
            scan = self.integrity_monitor.scan(
                self.store.get_integrity_manifest(),
                observed_at=started,
            )
            integrity_events = list(scan.events)
            integrity_manifest = scan.manifest
            if scan.truncated:
                errors.append("optional self-integrity inventory truncated")
                coverage_domains.append(
                    degraded_domain(
                        "self_integrity",
                        reason_code="inventory_truncated",
                    )
                )
            else:
                coverage_domains.append(complete_domain("self_integrity"))
        phases["self_integrity"] = self._elapsed_ms(phase)

        phase = time.perf_counter()
        scanner_events: list[SecurityEvent] = []
        freshness = ScannerFreshnessInspector(now=lambda: started)
        stale_scanners: set[int] = set()
        for index, job in enumerate(self.config.scanners):
            if not job.enabled:
                continue
            event = freshness.event(job, self.collector.host_id)
            if event is not None:
                scanner_events.append(event)
                stale_scanners.add(index)

        scanner_runs = 0
        for index, job in enumerate(self.config.scanners):
            coverage_name = f"scanner:{job.scanner}:{index}"
            if not job.enabled:
                coverage_domains.append(domain(coverage_name, enabled=False))
                continue
            if not self._scanner_due(job.scanner, job.interval_seconds, started):
                coverage_domains.append(not_due_domain(coverage_name))
                continue
            job_ran = False
            job_errors = 0
            for scanner_result in self.scanner_executor.run(job):
                job_ran = True
                scanner_runs += 1
                scanner_events.extend(scanner_result.events)
                self.store.record_scanner_run(scanner_result.to_dict())
                if scanner_result.error:
                    job_errors += 1
                    errors.append(f"optional {job.scanner} scan: {scanner_result.error}")
            if not job_ran:
                coverage_domains.append(
                    degraded_domain(coverage_name, reason_code="scanner_no_result")
                )
            elif job_errors:
                coverage_domains.append(
                    degraded_domain(
                        coverage_name,
                        reason_code="scanner_error",
                        issue_count=job_errors,
                    )
                )
            elif index in stale_scanners:
                coverage_domains.append(
                    degraded_domain(
                        coverage_name,
                        reason_code="scanner_data_stale",
                    )
                )
            else:
                coverage_domains.append(complete_domain(coverage_name))
        phases["scanner"] = self._elapsed_ms(phase)

        coverage = coverage_report(coverage_domains)
        coverage_dict = coverage.to_dict()
        coverage_dict["operationally_healthy"] = operationally_healthy(coverage_domains)
        coverage_dict.update(cadence_counts(coverage_domains))
        coverage_dict["cadence"] = decision.to_dict()

        all_events = [
            *collector_batch.events,
            *scanner_events,
            *integrity_events,
            *extra_events,
        ]
        phase = time.perf_counter()
        kept, suppressed = self.store.filter_suppressed_events(all_events, now=started)
        phases["suppression"] = self._elapsed_ms(phase)

        batch = CollectionBatch(collector_batch.snapshot, tuple(kept))
        phase = time.perf_counter()
        analysis = self.pipeline.analyze(kept)
        phases["analysis"] = self._elapsed_ms(phase)

        completed = self.clock()
        phase = time.perf_counter()
        persisted = self.store.persist_cycle(
            batch,
            analysis,
            started_at=started,
            completed_at=completed,
        )
        phases["persistence"] = self._elapsed_ms(phase)

        phase = time.perf_counter()
        coverage_dict["baseline"] = self.baseline_tracker.observe(
            coverage_dict["domains"],
            observed_at=completed,
        )
        phases["baseline"] = self._elapsed_ms(phase)

        lifecycle: dict[str, Any] | None = None
        phase = time.perf_counter()
        if self.lifecycle_repository is not None:
            self.lifecycle_repository.catch_up_from_evidence_chain(
                up_to_cycle_id=persisted.cycle_id - 1
            )
            lifecycle = self.lifecycle_repository.reconcile_cycle(
                persisted.cycle_id,
                (finding.to_dict() for finding in analysis.findings),
                (event.to_dict() for event in batch.events),
                observed_at=completed,
                coverage_complete=coverage.resolution_safe,
                coverage_domains=coverage_dict["domains"],
            ).to_dict()
        phases["lifecycle"] = self._elapsed_ms(phase)

        phase = time.perf_counter()
        if integrity_manifest is not None:
            self.store.set_integrity_manifest(integrity_manifest)
        coverage_value, coverage_error = self._persist_coverage_metadata(
            coverage_dict,
            cycle_id=persisted.cycle_id,
            observed_at=completed,
        )
        if coverage_error:
            errors.append(coverage_error)
        phases["auxiliary_metadata"] = self._elapsed_ms(phase)

        phase = time.perf_counter()
        alerts = self.alert_sink.emit_pending(self.store)
        phases["alerts"] = self._elapsed_ms(phase)
        phases["total_before_health"] = self._elapsed_ms(cycle_perf)

        command_count = max(
            0.0,
            command_after["commands_executed"] - command_before["commands_executed"],
        )
        command_ms = max(
            0.0,
            command_after["command_duration_ms"] - command_before["command_duration_ms"],
        )
        context: dict[str, object] = {
            "due_lanes": [lane.value for lane in decision.due_lanes],
            "scheduled_not_due": coverage_dict["scheduled_not_due"],
            "degraded_required": coverage_dict["degraded_required"],
            "baseline_confidence": coverage_dict["baseline"]["confidence"],
            "external_commands": int(command_count),
            "external_command_ms": round(command_ms, 3),
            "events": len(kept),
            "findings": len(analysis.findings),
            "scanner_runs": scanner_runs,
        }
        context.update(self._resource_context())
        self.runtime_metrics.record(phases, context=context)

        result = ServiceCycleResult(
            started,
            completed,
            persisted,
            len(collector_batch.events),
            len(scanner_events),
            len(integrity_events) + len(extra_events),
            len(suppressed),
            len(analysis.findings),
            alerts,
            scanner_runs,
            lifecycle,
            coverage_value,
            tuple(errors),
        )
        self.last_result = result
        self.consecutive_failures = 0
        self.cadence_controller.mark_completed(decision.due_lanes)
        self._safe_write_health("healthy", result=result)
        return result
