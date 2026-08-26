from __future__ import annotations

import hashlib
import json
import os
import signal
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .alerts import LocalAlertSink
from .collectors import CollectionBatch, build_collector
from .config import SentinelConfig
from .contracts import EventKind, SecurityEvent
from .coverage import (
    collector_coverage,
    complete_domain,
    degraded_domain,
    domain,
    not_due_domain,
    report as coverage_report,
)
from .freshness import ScannerFreshnessInspector
from .integrity import SelfIntegrityMonitor
from .locking import SingleInstanceLock
from .pipeline import SentinelPipeline
from .scanners import ScannerExecutor
from .source_aware_lifecycle import SourceAwareIncidentLifecycleRepository
from .storage import PersistResult, SentinelStore
from .suppression import partition_for_suppression


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    temporary = path.with_name(
        f".{path.name}.tmp-{os.getpid()}-{threading.get_ident()}-{time.time_ns()}"
    )
    data = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short health-file write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        try:
            directory_flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                directory_flags |= os.O_DIRECTORY
            directory = os.open(path.parent, directory_flags)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            pass
    except Exception:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


@dataclass(frozen=True, slots=True)
class ServiceCycleResult:
    started_at: datetime
    completed_at: datetime
    persist: PersistResult
    collector_events: int
    scanner_events: int
    integrity_events: int
    suppressed_events: int
    findings: int
    alerts_emitted: int
    scanner_runs: int
    lifecycle: dict[str, Any] | None
    coverage: dict[str, Any] | None
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "completed_at": self.completed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "collector_events": self.collector_events,
            "scanner_events": self.scanner_events,
            "integrity_events": self.integrity_events,
            "suppressed_events": self.suppressed_events,
            "findings": self.findings,
            "alerts_emitted": self.alerts_emitted,
            "scanner_runs": self.scanner_runs,
            "lifecycle": self.lifecycle,
            "coverage": self.coverage,
            "errors": list(self.errors),
            "events_inserted": self.persist.events_inserted,
            "findings_inserted": self.persist.findings_inserted,
            "chain_hash": self.persist.chain_hash,
            "actions_executed": 0,
        }


class SentinelService:
    def __init__(
        self,
        config: SentinelConfig,
        *,
        collector=None,
        pipeline=None,
        store=None,
        scanner_executor=None,
        alert_sink=None,
        integrity_monitor: SelfIntegrityMonitor | None = None,
        lifecycle_repository=None,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.config = config
        self.collector = collector or build_collector(config.collector)
        self.pipeline = pipeline or SentinelPipeline()
        self.store = store or SentinelStore(config.storage)
        self.scanner_executor = scanner_executor or ScannerExecutor(self.collector.host_id)
        self.alert_sink = alert_sink or LocalAlertSink(config.storage.alert_log_path)
        self.integrity_monitor = integrity_monitor
        if lifecycle_repository is not None:
            self.lifecycle_repository = lifecycle_repository
        else:
            connection = getattr(self.store, "connection", None)
            self.lifecycle_repository = (
                SourceAwareIncidentLifecycleRepository(connection)
                if connection is not None
                else None
            )
        self.sleeper = sleeper
        self.clock = clock
        self.stop_event = threading.Event()
        self.consecutive_failures = 0
        self.owns_store = store is None
        self.last_result = None

    def close(self) -> None:
        if self.owns_store:
            self.store.close()

    def request_stop(self) -> None:
        self.stop_event.set()

    def install_signal_handlers(self) -> None:
        signal.signal(signal.SIGTERM, lambda *_: self.request_stop())
        signal.signal(signal.SIGINT, lambda *_: self.request_stop())

    def _evidence_failure_event(self, chain: dict[str, Any], observed_at: datetime) -> SecurityEvent:
        digest = hashlib.sha256(
            f"{self.collector.host_id}|chain|{json.dumps(chain, sort_keys=True)}|{observed_at.isoformat()}".encode()
        ).hexdigest()[:20]
        return SecurityEvent(
            "qwd-" + digest,
            observed_at,
            self.collector.host_id,
            "quietward_evidence_chain",
            EventKind.EVIDENCE_INTEGRITY_FAILURE,
            "quietward:evidence-chain",
            {
                "errors": chain.get("errors", [])[:20],
                "cycles_checked": chain.get("cycles_checked", 0),
                "privileged_context": True,
                "baseline_deviation": 1.0,
                "authoritative_rule_match": True,
            },
            1.0,
        )

    @staticmethod
    def _coverage_value(
        coverage: dict[str, Any],
        *,
        cycle_id: int,
        observed_at: datetime,
        metadata_persisted: bool,
    ) -> dict[str, Any]:
        value = dict(coverage)
        value["cycle_id"] = cycle_id
        value["observed_at"] = observed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        value["metadata_persisted"] = metadata_persisted
        value["actions_executed"] = 0
        return value

    def _persist_coverage_metadata(
        self,
        coverage: dict[str, Any],
        *,
        cycle_id: int,
        observed_at: datetime,
    ) -> tuple[dict[str, Any], str | None]:
        connection = getattr(self.store, "connection", None)
        set_metadata = getattr(self.store, "set_metadata", None)
        if connection is None or not callable(set_metadata):
            return (
                self._coverage_value(coverage, cycle_id=cycle_id, observed_at=observed_at, metadata_persisted=False),
                "coverage metadata storage unavailable",
            )
        persisted = self._coverage_value(
            coverage,
            cycle_id=cycle_id,
            observed_at=observed_at,
            metadata_persisted=True,
        )
        try:
            with connection:
                set_metadata(
                    "last_coverage_report",
                    json.dumps(persisted, sort_keys=True, separators=(",", ":")),
                )
        except (OSError, TypeError, ValueError, sqlite3.Error):
            return (
                self._coverage_value(coverage, cycle_id=cycle_id, observed_at=observed_at, metadata_persisted=False),
                "coverage metadata persistence failed",
            )
        return persisted, None

    def run_cycle(self) -> ServiceCycleResult:
        started = self.clock()
        previous = self.store.latest_snapshot()
        collector_batch = self.collector.collect(previous)
        extra_events: list[SecurityEvent] = []
        errors = list(collector_batch.snapshot.errors)
        coverage_domains = list(
            collector_coverage(
                self.config.collector,
                collector_batch.snapshot.errors,
                collector_version=collector_batch.snapshot.collector_version,
            )
        )

        chain = self.store.verify_evidence_chain()
        if chain["cycles_checked"] and not chain["valid"]:
            extra_events.append(self._evidence_failure_event(chain, started))
            coverage_domains.append(degraded_domain("evidence_chain", reason_code="evidence_integrity_invalid"))
        else:
            coverage_domains.append(complete_domain("evidence_chain"))

        integrity_events: list[SecurityEvent] = []
        integrity_manifest = None
        if not self.config.self_integrity.enabled:
            coverage_domains.append(domain("self_integrity", enabled=False))
        elif self.integrity_monitor is None:
            coverage_domains.append(degraded_domain("self_integrity", reason_code="monitor_unavailable"))
        else:
            scan = self.integrity_monitor.scan(self.store.get_integrity_manifest(), observed_at=started)
            integrity_events = list(scan.events)
            integrity_manifest = scan.manifest
            if scan.truncated:
                errors.append("optional self-integrity inventory truncated")
                coverage_domains.append(degraded_domain("self_integrity", reason_code="inventory_truncated"))
            else:
                coverage_domains.append(complete_domain("self_integrity"))

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
                coverage_domains.append(degraded_domain(coverage_name, reason_code="scanner_no_result"))
            elif job_errors:
                coverage_domains.append(degraded_domain(coverage_name, reason_code="scanner_error", issue_count=job_errors))
            elif index in stale_scanners:
                coverage_domains.append(degraded_domain(coverage_name, reason_code="scanner_data_stale"))
            else:
                coverage_domains.append(complete_domain(coverage_name))

        coverage = coverage_report(coverage_domains)
        all_events = [*collector_batch.events, *scanner_events, *integrity_events, *extra_events]
        bypass, suppression_eligible = partition_for_suppression(all_events)
        kept, suppressed = self.store.filter_suppressed_events(
            suppression_eligible,
            now=started,
        )
        kept = [*bypass, *kept]
        batch = CollectionBatch(collector_batch.snapshot, tuple(kept))
        report = self.pipeline.analyze(kept)
        completed = self.clock()
        persisted = self.store.persist_cycle(batch, report, started_at=started, completed_at=completed)

        lifecycle: dict[str, Any] | None = None
        if self.lifecycle_repository is not None:
            self.lifecycle_repository.catch_up_from_evidence_chain(up_to_cycle_id=persisted.cycle_id - 1)
            lifecycle = self.lifecycle_repository.reconcile_cycle(
                persisted.cycle_id,
                (finding.to_dict() for finding in report.findings),
                (event.to_dict() for event in batch.events),
                observed_at=completed,
                coverage_complete=coverage.resolution_safe,
                coverage_domains=coverage.to_dict()["domains"],
            ).to_dict()

        if integrity_manifest is not None:
            self.store.set_integrity_manifest(integrity_manifest)

        coverage_value, coverage_error = self._persist_coverage_metadata(
            coverage.to_dict(),
            cycle_id=persisted.cycle_id,
            observed_at=completed,
        )
        if coverage_error:
            errors.append(coverage_error)

        alerts = self.alert_sink.emit_pending(self.store)
        result = ServiceCycleResult(
            started,
            completed,
            persisted,
            len(collector_batch.events),
            len(scanner_events),
            len(integrity_events) + len(extra_events),
            len(suppressed),
            len(report.findings),
            alerts,
            scanner_runs,
            lifecycle,
            coverage_value,
            tuple(errors),
        )
        self.last_result = result
        self.consecutive_failures = 0
        self._safe_write_health("healthy", result=result)
        return result

    def run(self, max_cycles: int | None = None) -> int:
        if max_cycles is not None and max_cycles <= 0:
            raise ValueError("max_cycles must be positive")
        successful_cycles = 0
        self.install_signal_handlers()
        with SingleInstanceLock(self.config.service.lock_path):
            self._safe_write_health("starting")
            while not self.stop_event.is_set():
                try:
                    self.run_cycle()
                    successful_cycles += 1
                except Exception as exc:
                    self.consecutive_failures += 1
                    self._safe_write_health("degraded", error=str(exc)[:500])
                    if max_cycles is not None:
                        self._safe_write_health("failed", error="bounded observation cycle failed")
                        return 1
                    if self.consecutive_failures >= self.config.service.stop_after_failures:
                        self._safe_write_health("failed", error="consecutive failure limit reached")
                        return 1
                if max_cycles is not None and successful_cycles >= max_cycles:
                    break
                if self.stop_event.wait(self.config.collector.interval_seconds):
                    break
            self._safe_write_health("stopped")
        return 0

    def _scanner_due(self, scanner: str, interval_seconds: float, now: datetime) -> bool:
        previous = self.store.scanner_last_run(scanner)
        return previous is None or (now - previous).total_seconds() >= interval_seconds

    def _safe_write_health(self, status: str, *, result=None, error=None) -> None:
        try:
            self._write_health(status, result=result, error=error)
        except Exception:
            try:
                _atomic_json(
                    self.config.service.health_path,
                    {
                        "service": "quietward",
                        "status": status,
                        "observed_at": self.clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "consecutive_failures": self.consecutive_failures,
                        "last_cycle": None,
                        "error": error or "health summary unavailable",
                        "storage": None,
                        "coverage": None,
                        "safety": {
                            "mode": "observe_only",
                            "actions_executed": 0,
                            "shell_used": False,
                            "sudo_used": False,
                            "system_state_modified": False,
                            "own_state_written": True,
                        },
                    },
                )
            except Exception:
                pass

    def _write_health(self, status: str, *, result=None, error=None) -> None:
        current_result = result or self.last_result
        value = {
            "service": "quietward",
            "status": status,
            "observed_at": self.clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "consecutive_failures": self.consecutive_failures,
            "last_cycle": current_result.to_dict() if current_result else None,
            "error": error,
            "storage": self.store.summary(),
            "lifecycle": self.lifecycle_repository.summary() if self.lifecycle_repository is not None else None,
            "coverage": current_result.coverage if current_result else None,
            "safety": {
                "mode": "observe_only",
                "actions_executed": 0,
                "shell_used": False,
                "sudo_used": False,
                "system_state_modified": False,
                "own_state_written": True,
            },
        }
        _atomic_json(self.config.service.health_path, value)


QuietWardService = SentinelService
