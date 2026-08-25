from __future__ import annotations

import hashlib
import shutil
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from .config import ScannerJobSettings
from .contracts import EventKind, SecurityEvent


_DEFAULT_MAX_AGE_HOURS = {
    "clamav": 72.0,
    "yara": 24.0 * 30.0,
    "trivy": 24.0 * 7.0,
    "debsecan": 72.0,
}


@dataclass(frozen=True, slots=True)
class FreshnessStatus:
    scanner: str
    enabled: bool
    binary_available: bool
    data_present: bool
    data_path: str | None
    newest_mtime: datetime | None
    age_hours: float | None
    max_age_hours: float
    stale: bool
    details: str

    def to_dict(self) -> dict[str, object]:
        return {
            "scanner": self.scanner,
            "enabled": self.enabled,
            "binary_available": self.binary_available,
            "data_present": self.data_present,
            "data_path": self.data_path,
            "newest_mtime": (
                self.newest_mtime.astimezone(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
                if self.newest_mtime
                else None
            ),
            "age_hours": round(self.age_hours, 3) if self.age_hours is not None else None,
            "max_age_hours": self.max_age_hours,
            "stale": self.stale,
            "details": self.details,
            "network_update_performed": False,
        }


class ScannerFreshnessInspector:
    _cache: dict[tuple[object, ...], tuple[datetime, FreshnessStatus]] = {}
    _event_cache: dict[str, datetime] = {}
    _cache_lock = threading.Lock()

    def __init__(
        self,
        now: callable = lambda: datetime.now(timezone.utc),
        *,
        discovery_cache_seconds: float = 300.0,
        event_repeat_seconds: float = 300.0,
    ) -> None:
        if discovery_cache_seconds <= 0 or event_repeat_seconds <= 0:
            raise ValueError("freshness cache intervals must be positive")
        self.now = now
        self.discovery_cache_seconds = float(discovery_cache_seconds)
        self.event_repeat_seconds = float(event_repeat_seconds)

    @classmethod
    def clear_cache(cls) -> None:
        with cls._cache_lock:
            cls._cache.clear()
            cls._event_cache.clear()

    @staticmethod
    def _key(job: ScannerJobSettings) -> tuple[object, ...]:
        return (
            job.scanner,
            bool(job.enabled),
            str(job.rules_path) if job.rules_path is not None else None,
            str(job.data_source) if job.data_source is not None else None,
            float(job.max_data_age_hours) if job.max_data_age_hours is not None else None,
        )

    def _refresh_age(
        self,
        status: FreshnessStatus,
        now: datetime,
    ) -> FreshnessStatus:
        if status.newest_mtime is None:
            return status
        age = max(
            0.0,
            (now - status.newest_mtime).total_seconds() / 3600.0,
        )
        stale = age > status.max_age_hours
        return replace(
            status,
            age_hours=age,
            stale=stale,
            details=(
                "data age exceeds configured maximum"
                if stale
                else "data freshness is within configured maximum"
            ),
        )

    def inspect(self, job: ScannerJobSettings) -> FreshnessStatus:
        now = self.now().astimezone(timezone.utc)
        key = self._key(job)
        with self._cache_lock:
            cached = self._cache.get(key)
        if cached is not None:
            checked_at, status = cached
            elapsed = (now - checked_at).total_seconds()
            if 0.0 <= elapsed < self.discovery_cache_seconds:
                return self._refresh_age(status, now)

        status = self._inspect_uncached(job, now)
        with self._cache_lock:
            self._cache[key] = (now, status)
            if len(self._cache) > 128:
                oldest = min(self._cache, key=lambda item: self._cache[item][0])
                self._cache.pop(oldest, None)
        return status

    def _inspect_uncached(
        self,
        job: ScannerJobSettings,
        now: datetime,
    ) -> FreshnessStatus:
        binary = "clamscan" if job.scanner == "clamav" else job.scanner
        available = shutil.which(binary) is not None
        max_age = float(
            job.max_data_age_hours or _DEFAULT_MAX_AGE_HOURS[job.scanner]
        )
        candidates = self._candidate_files(job)
        existing = [path for path in candidates if path.exists() and path.is_file()]
        if not existing:
            return FreshnessStatus(
                job.scanner,
                job.enabled,
                available,
                False,
                str(job.data_source or job.rules_path)
                if (job.data_source or job.rules_path)
                else None,
                None,
                None,
                max_age,
                bool(job.enabled),
                "scanner data or rules were not found",
            )
        newest_path = max(existing, key=lambda path: path.stat().st_mtime_ns)
        newest = datetime.fromtimestamp(newest_path.stat().st_mtime, tz=timezone.utc)
        age = max(0.0, (now - newest).total_seconds() / 3600.0)
        return FreshnessStatus(
            job.scanner,
            job.enabled,
            available,
            True,
            str(newest_path),
            newest,
            age,
            max_age,
            age > max_age,
            (
                "data age exceeds configured maximum"
                if age > max_age
                else "data freshness is within configured maximum"
            ),
        )

    def event(self, job: ScannerJobSettings, host_id: str) -> SecurityEvent | None:
        status = self.inspect(job)
        if not job.enabled or not status.stale:
            return None
        now = self.now().astimezone(timezone.utc)
        digest = hashlib.sha256(
            f"{host_id}|freshness|{job.scanner}|{status.data_path}|{status.newest_mtime}".encode(
                "utf-8"
            )
        ).hexdigest()[:20]
        event_id = "fse-" + digest
        with self._cache_lock:
            previous = self._event_cache.get(event_id)
            if previous is not None:
                elapsed = (now - previous).total_seconds()
                if 0.0 <= elapsed < self.event_repeat_seconds:
                    return None
            self._event_cache[event_id] = now
            if len(self._event_cache) > 256:
                oldest = min(self._event_cache, key=self._event_cache.get)
                self._event_cache.pop(oldest, None)
        return SecurityEvent(
            event_id=event_id,
            observed_at=now,
            host_id=host_id,
            source="scanner_freshness_read_only",
            kind=EventKind.CONFIGURATION_WEAKNESS,
            subject=f"scanner:{job.scanner}",
            attributes={
                "scanner": job.scanner,
                "binary_available": status.binary_available,
                "data_present": status.data_present,
                "age_hours": status.age_hours,
                "max_age_hours": status.max_age_hours,
                "stale": True,
                "network_update_performed": False,
            },
            confidence=1.0,
        )

    def _candidate_files(self, job: ScannerJobSettings) -> list[Path]:
        if job.scanner == "yara":
            return [job.rules_path] if job.rules_path else []
        if job.data_source:
            if job.data_source.is_file():
                return [job.data_source]
            if job.data_source.is_dir():
                return self._files(job.data_source, job.scanner)
            return []
        if job.scanner == "clamav":
            return [
                item
                for root in [Path("/var/lib/clamav"), Path("/usr/local/share/clamav")]
                for item in self._files(root, "clamav")
            ]
        if job.scanner == "trivy":
            return self._files(Path.home() / ".cache" / "trivy" / "db", "trivy")
        return []

    @staticmethod
    def _files(root: Path, scanner: str) -> list[Path]:
        if not root.exists() or not root.is_dir():
            return []
        suffixes = {
            "clamav": {".cvd", ".cld", ".cud"},
            "trivy": {".db", ".json", ".metadata"},
            "debsecan": {".json", ".data", ".db"},
        }.get(scanner, set())
        values: list[Path] = []
        for path in root.rglob("*"):
            try:
                if path.is_file() and (
                    not suffixes or path.suffix.lower() in suffixes
                ):
                    values.append(path)
            except OSError:
                continue
        return values[:10_000]
