from __future__ import annotations

import hashlib
import json
import os
import signal
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from .alerts import LocalAlertSink
from .collectors import CollectionBatch, build_collector
from .config import SentinelConfig
from .contracts import EventKind, SecurityEvent
from .freshness import ScannerFreshnessInspector
from .integrity import SelfIntegrityMonitor
from .locking import SingleInstanceLock
from .pipeline import SentinelPipeline
from .scanners import ScannerExecutor
from .storage import PersistResult, SentinelStore

if TYPE_CHECKING:
    from .response_client import QuietWardResponseClient


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    data = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short health-file write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


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
    errors: tuple[str, ...]
    response_events_sent: int = 0
    response_events_queued: int = 0
    response_demo_actions_executed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "completed_at": self.completed_at.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "collector_events": self.collector_events,
            "scanner_events": self.scanner_events,
            "integrity_events": self.integrity_events,
            "suppressed_events": self.suppressed_events,
            "findings": self.findings,
            "alerts_emitted": self.alerts_emitted,
            "scanner_runs": self.scanner_runs,
            "errors": list(self.errors),
            "events_inserted": self.persist.events_inserted,
            "findings_inserted": self.persist.findings_inserted,
            "chain_hash": self.persist.chain_hash,
            "response_events_sent": self.response_events_sent,
            "response_events_queued": self.response_events_queued,
            "response_demo_actions_executed": self.response_demo_actions_executed,
            # QuietWard still performs no general host remediation in this mode.
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
        response_client: QuietWardResponseClient | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.config = config
        self.collector = collector or build_collector(config.collector)
        self.pipeline = pipeline or SentinelPipeline()
        self.store = store or SentinelStore(config.storage)
        self.scanner_executor = scanner_executor or ScannerExecutor(
            self.collector.host_id
        )
        self.alert_sink = alert_sink or LocalAlertSink(
            config.storage.alert_log_path
        )
        self.integrity_monitor = integrity_monitor
        self.response_client = response_client
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

    def _evidence_failure_event(
        self,
        chain: dict[str, Any],
        observed_at: datetime,
    ) -> SecurityEvent:
        digest = hashlib.sha256(
            (
                f"{self.collector.host_id}|chain|"
                f"{json.dumps(chain, sort_keys=True)}|{observed_at.isoformat()}"
            ).encode()
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

    def run_cycle(self) -> ServiceCycleResult:
        started = self.clock()
        previous = self.store.latest_snapshot()
        collector_batch = self.collector.collect(previous)
        extra_events: list[SecurityEvent] = []
        errors = list(collector_batch.snapshot.errors)

        chain = self.store.verify_evidence_chain()
        if chain["cycles_checked"] and not chain["valid"]:
            extra_events.append(self._evidence_failure_event(chain, started))

        integrity_events: list[SecurityEvent] = []
        integrity_manifest = None
        if self.integrity_monitor is not None:
            scan = self.integrity_monitor.scan(
                self.store.get_integrity_manifest(),
                observed_at=started,
            )
            integrity_events = list(scan.events)
            integrity_manifest = scan.manifest
            if scan.truncated:
                errors.append("optional self-integrity inventory truncated")

        scanner_events: list[SecurityEvent] = []
        freshness = ScannerFreshnessInspector(now=lambda: started)
        for job in self.config.scanners:
            event = freshness.event(job, self.collector.host_id)
            if event is not None:
                scanner_events.append(event)

        scanner_runs = 0
        for job in self.config.scanners:
            if not job.enabled or not self._scanner_due(
                job.scanner,
                job.interval_seconds,
                started,
            ):
                continue
            for result in self.scanner_executor.run(job):
                scanner_runs += 1
                scanner_events.extend(result.events)
                self.store.record_scanner_run(result.to_dict())
                if result.error:
                    errors.append(f"optional {job.scanner} scan: {result.error}")

        all_events = [
            *collector_batch.events,
            *scanner_events,
            *integrity_events,
            *extra_events,
        ]
        kept, suppressed = self.store.filter_suppressed_events(
            all_events,
            now=started,
        )
        batch = CollectionBatch(collector_batch.snapshot, tuple(kept))
        report = self.pipeline.analyze(kept)
        completed = self.clock()
        persisted = self.store.persist_cycle(
            batch,
            report,
            started_at=started,
            completed_at=completed,
        )
        if integrity_manifest is not None:
            self.store.set_integrity_manifest(integrity_manifest)
        alerts = self.alert_sink.emit_pending(self.store)

        response_sent = 0
        response_queued = 0
        response_demo_actions = 0
        if self.response_client is not None:
            try:
                delivery = self.response_client.deliver_cycle(kept, report)
                response_sent = int(delivery.get("sent", 0))
                response_queued = int(delivery.get("queued", 0))
                response_demo_actions = self.response_client.poll_and_execute()
            except Exception as exc:
                # Response is optional: remote failure never stops local monitoring.
                errors.append(f"optional response integration: {str(exc)[:300]}")

        result = ServiceCycleResult(
            started_at=started,
            completed_at=completed,
            persist=persisted,
            collector_events=len(collector_batch.events),
            scanner_events=len(scanner_events),
            integrity_events=len(integrity_events) + len(extra_events),
            suppressed_events=len(suppressed),
            findings=len(report.findings),
            alerts_emitted=alerts,
            scanner_runs=scanner_runs,
            errors=tuple(errors),
            response_events_sent=response_sent,
            response_events_queued=response_queued,
            response_demo_actions_executed=response_demo_actions,
        )
        self.last_result = result
        self._write_health("healthy", result=result)
        self.consecutive_failures = 0
        return result

    def run(self, max_cycles: int | None = None) -> int:
        if max_cycles is not None and max_cycles <= 0:
            raise ValueError("max_cycles must be positive")
        cycles = 0
        self.install_signal_handlers()
        with SingleInstanceLock(self.config.service.lock_path):
            self._write_health("starting")
            while not self.stop_event.is_set():
                try:
                    self.run_cycle()
                except Exception as exc:
                    self.consecutive_failures += 1
                    self._write_health("degraded", error=str(exc)[:500])
                    if (
                        self.consecutive_failures
                        >= self.config.service.stop_after_failures
                    ):
                        self._write_health(
                            "failed",
                            error="consecutive failure limit reached",
                        )
                        return 1
                cycles += 1
                if max_cycles is not None and cycles >= max_cycles:
                    break
                if self.stop_event.wait(self.config.collector.interval_seconds):
                    break
            self._write_health("stopped")
        return 0

    def _scanner_due(
        self,
        scanner: str,
        interval_seconds: float,
        now: datetime,
    ) -> bool:
        previous = self.store.scanner_last_run(scanner)
        return previous is None or (
            now - previous
        ).total_seconds() >= interval_seconds

    def _write_health(
        self,
        status: str,
        *,
        result=None,
        error=None,
    ) -> None:
        current_result = result or self.last_result
        value = {
            "service": "quietward",
            "status": status,
            "observed_at": self.clock()
            .astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "consecutive_failures": self.consecutive_failures,
            "last_cycle": current_result.to_dict() if current_result else None,
            "error": error,
            "storage": self.store.summary(),
            "safety": {
                "mode": "observe_only_with_optional_demo_response",
                "actions_executed": 0,
                "response_demo_actions_executed": (
                    current_result.response_demo_actions_executed if current_result else 0
                ),
                "response_integration_enabled": self.response_client is not None,
                "shell_used": False,
                "sudo_used": False,
                "system_state_modified": False,
                "own_state_written": True,
            },
        }
        _atomic_json(self.config.service.health_path, value)


QuietWardService = SentinelService
