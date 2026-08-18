from __future__ import annotations

import hashlib
import json
import platform
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

try:
    import resource
except ImportError:  # Windows
    resource = None  # type: ignore[assignment]

from .collectors import CollectionBatch, CollectorSnapshot
from .contracts import EventKind


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class QualificationConfig:
    cycles: int = 3
    interval_seconds: float = 1.0
    max_cycle_ms: float = 5_000.0
    max_snapshot_bytes: int = 2_000_000
    max_peak_rss_bytes: int = 512 * 1024 * 1024
    max_events_per_cycle: int = 500

    def __post_init__(self) -> None:
        if self.cycles <= 0:
            raise ValueError("cycles must be positive")
        if self.interval_seconds < 0:
            raise ValueError("interval_seconds must be nonnegative")
        if (
            self.max_cycle_ms <= 0
            or self.max_snapshot_bytes <= 0
            or self.max_peak_rss_bytes <= 0
            or self.max_events_per_cycle <= 0
        ):
            raise ValueError("qualification limits must be positive")


@dataclass(frozen=True, slots=True)
class QualificationCycle:
    index: int
    observed_at: datetime
    duration_ms: float
    snapshot_bytes: int
    events_count: int
    peak_rss_bytes: int | None
    collector_errors: tuple[str, ...]
    actions_executed: int = 0

    def to_dict(self):
        return {
            "index": self.index,
            "observed_at": _utc(self.observed_at),
            "duration_ms": self.duration_ms,
            "snapshot_bytes": self.snapshot_bytes,
            "events_count": self.events_count,
            "peak_rss_bytes": self.peak_rss_bytes,
            "collector_errors": list(self.collector_errors),
            "actions_executed": self.actions_executed,
        }


@dataclass(frozen=True, slots=True)
class QualificationReport:
    report_id: str
    created_at: datetime
    host_id: str
    decision: str
    cycles: tuple[QualificationCycle, ...]
    blockers: tuple[str, ...]
    warnings: tuple[str, ...]
    limits: QualificationConfig

    def to_dict(self):
        return {
            "format": "quietward-target-host-qualification-v1",
            "report_id": self.report_id,
            "created_at": _utc(self.created_at),
            "host_id": self.host_id,
            "decision": self.decision,
            "cycles": [cycle.to_dict() for cycle in self.cycles],
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
            "limits": {
                "cycles": self.limits.cycles,
                "interval_seconds": self.limits.interval_seconds,
                "max_cycle_ms": self.limits.max_cycle_ms,
                "max_snapshot_bytes": self.limits.max_snapshot_bytes,
                "max_peak_rss_bytes": self.limits.max_peak_rss_bytes,
                "max_events_per_cycle": self.limits.max_events_per_cycle,
            },
            "safety": {
                "mode": "observe_only",
                "actions_executed": 0,
                "executable_proposals": 0,
                "shell_used": False,
                "sudo_used": False,
                "host_modified": False,
                "scanner_executed": False,
                "network_used": False,
            },
        }


def current_peak_rss_bytes() -> int | None:
    if resource is None:
        return None
    try:
        value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except (ValueError, OSError):
        return None
    return value if platform.system() == "Darwin" else value * 1024


class TargetHostQualifier:
    BASELINE_CHANGE_KINDS = {
        EventKind.PROCESS_START,
        EventKind.NEW_LISTENING_PORT,
        EventKind.OUTBOUND_CONNECTION,
        EventKind.CONTAINER_CHANGE,
        EventKind.CONTAINER_CONFIGURATION_CHANGE,
        EventKind.FILE_CHANGE,
        EventKind.SENSITIVE_FILE_CHANGE,
        EventKind.ACCOUNT_CHANGE,
        EventKind.PERSISTENCE_CHANGE,
    }
    PRIVACY_FLAGS = {
        "raw_arguments_persisted",
        "raw_source_address_persisted",
        "raw_log_message_persisted",
        "raw_container_id_persisted",
        "raw_file_content_persisted",
        "raw_remote_address_persisted",
        "raw_local_address_persisted",
        "raw_persistence_content_persisted",
        "raw_authorized_keys_persisted",
        "raw_username_persisted",
    }
    REQUIRED_PRIVACY_FLAGS = {
        EventKind.PROCESS_START: {"raw_arguments_persisted", "raw_username_persisted"},
        EventKind.AUTH_FAILURE: {"raw_source_address_persisted", "raw_username_persisted", "raw_log_message_persisted"},
        EventKind.OUTBOUND_CONNECTION: {"raw_remote_address_persisted", "raw_local_address_persisted"},
        EventKind.CONTAINER_CHANGE: {"raw_container_id_persisted"},
        EventKind.CONTAINER_CONFIGURATION_CHANGE: {"raw_container_id_persisted"},
        EventKind.FILE_CHANGE: {"raw_file_content_persisted"},
        EventKind.SENSITIVE_FILE_CHANGE: {"raw_file_content_persisted"},
        EventKind.ACCOUNT_CHANGE: {"raw_persistence_content_persisted", "raw_authorized_keys_persisted"},
        EventKind.PERSISTENCE_CHANGE: {"raw_persistence_content_persisted", "raw_authorized_keys_persisted"},
    }

    def __init__(
        self,
        collector,
        config: QualificationConfig | None = None,
        *,
        timer: Callable[[], float] = time.perf_counter,
        sleeper: Callable[[float], None] = time.sleep,
        rss_reader: Callable[[], int | None] = current_peak_rss_bytes,
    ) -> None:
        self.collector = collector
        self.config = config or QualificationConfig()
        self.timer = timer
        self.sleeper = sleeper
        self.rss_reader = rss_reader

    def run(self) -> QualificationReport:
        previous: CollectorSnapshot | None = None
        cycles: list[QualificationCycle] = []
        blockers: list[str] = []
        warnings: list[str] = []
        host_id: str | None = None
        for index in range(1, self.config.cycles + 1):
            started = self.timer()
            try:
                batch = self.collector.collect(previous)
            except Exception as exc:
                blockers.append(
                    f"cycle {index}: collector raised "
                    f"{type(exc).__name__}: {str(exc)[:200]}"
                )
                break
            duration_ms = (self.timer() - started) * 1000.0
            payload = json.dumps(
                batch.snapshot.to_dict(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            rss = self.rss_reader()
            cycles.append(
                QualificationCycle(
                    index,
                    batch.snapshot.observed_at,
                    round(duration_ms, 3),
                    len(payload),
                    len(batch.events),
                    rss,
                    batch.snapshot.errors,
                )
            )
            host_id = host_id or batch.snapshot.host_id
            blockers.extend(
                self._validate_cycle(
                    index,
                    batch,
                    duration_ms,
                    len(payload),
                    rss,
                    host_id,
                )
            )
            warnings.extend(
                f"cycle {index}: {error}"
                for error in batch.snapshot.errors
                if "optional" in error.lower()
            )
            previous = batch.snapshot
            if index < self.config.cycles and self.config.interval_seconds:
                self.sleeper(self.config.interval_seconds)

        if len(cycles) != self.config.cycles:
            blockers.append(
                f"completed {len(cycles)} of {self.config.cycles} requested cycles"
            )
        created = datetime.now(timezone.utc)
        normalized_host = host_id or "unavailable"
        report_id = "qwdq-" + hashlib.sha256(
            f"{normalized_host}|{created.isoformat()}|{len(cycles)}".encode()
        ).hexdigest()[:16]
        return QualificationReport(
            report_id,
            created,
            normalized_host,
            "PASS" if not blockers else "FAIL",
            tuple(cycles),
            tuple(blockers),
            tuple(warnings),
            self.config,
        )

    def _validate_cycle(
        self,
        index: int,
        batch: CollectionBatch,
        duration_ms: float,
        snapshot_bytes: int,
        rss: int | None,
        expected_host_id: str,
    ) -> list[str]:
        blockers: list[str] = []
        if batch.snapshot.host_id != expected_host_id:
            blockers.append(f"cycle {index}: host ID changed")
        if duration_ms > self.config.max_cycle_ms:
            blockers.append(
                f"cycle {index}: duration {duration_ms:.3f} ms exceeds limit"
            )
        if snapshot_bytes > self.config.max_snapshot_bytes:
            blockers.append(
                f"cycle {index}: snapshot size {snapshot_bytes} exceeds limit"
            )
        if len(batch.events) > self.config.max_events_per_cycle:
            blockers.append(f"cycle {index}: event count exceeds limit")
        if rss is not None and rss > self.config.max_peak_rss_bytes:
            blockers.append(f"cycle {index}: peak RSS {rss} exceeds limit")
        if index == 1:
            change_events = [
                event.kind.value
                for event in batch.events
                if event.kind in self.BASELINE_CHANGE_KINDS
            ]
            if change_events:
                blockers.append(
                    f"cycle 1 baseline emitted change events: "
                    f"{', '.join(change_events[:10])}"
                )
        for event in batch.events:
            present_flags = self.PRIVACY_FLAGS.intersection(event.attributes)
            required_flags = self.REQUIRED_PRIVACY_FLAGS.get(event.kind, set())
            for flag in present_flags.union(required_flags):
                if event.attributes.get(flag) is not False:
                    blockers.append(
                        f"cycle {index}: {event.event_id} privacy flag "
                        f"{flag} is not false"
                    )
        for error in batch.snapshot.errors:
            if "optional" not in error.lower():
                blockers.append(f"cycle {index}: required collector error: {error}")
        return blockers
