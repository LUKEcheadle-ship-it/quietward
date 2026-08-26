from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from .contracts import EventKind, SecurityEvent


def _file_metadata(path: Path, max_bytes: int) -> tuple[int, int, int, int] | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > max_bytes:
        return None
    return stat.S_IMODE(info.st_mode), info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _hash_file(path: Path, max_bytes: int) -> tuple[str, int, int, int, int] | None:
    metadata = _file_metadata(path, max_bytes)
    if metadata is None:
        return None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
                return None
            hasher = hashlib.sha256()
            while chunk := os.read(descriptor, 128 * 1024):
                hasher.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        return None
    if before.st_dev != after.st_dev or before.st_ino != after.st_ino or before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns:
        return None
    return hasher.hexdigest(), stat.S_IMODE(after.st_mode), after.st_size, after.st_mtime_ns, after.st_ctime_ns


def _sample_file(path: Path, max_bytes: int, sample_bytes: int = 4 * 1024) -> str | None:
    """Return a bounded change token without following links.

    Some supported filesystems expose timestamps too coarsely to distinguish two
    same-size writes.  Sampling the beginning and end keeps the fast-path bounded
    while forcing a full hash when common metadata-preserving tampering occurs.
    The periodic full audit remains the authoritative whole-file check.
    """

    metadata = _file_metadata(path, max_bytes)
    if metadata is None:
        return None
    _mode, size, _mtime_ns, _ctime_ns = metadata
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size != size:
                return None
            first = os.read(descriptor, min(sample_bytes, size))
            last = b""
            if size > sample_bytes:
                os.lseek(descriptor, max(0, size - sample_bytes), os.SEEK_SET)
                last = os.read(descriptor, sample_bytes)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        return None
    if before.st_dev != after.st_dev or before.st_ino != after.st_ino or before.st_size != after.st_size:
        return None
    token = hashlib.sha256()
    token.update(str(size).encode("ascii"))
    token.update(b"\0")
    token.update(first)
    token.update(b"\0")
    token.update(last)
    return token.hexdigest()


@dataclass(frozen=True, slots=True)
class IntegrityScan:
    manifest: dict[str, dict[str, object]]
    events: tuple[SecurityEvent, ...]
    truncated: bool = False
    files_hashed: int = 0
    hashes_reused: int = 0
    full_hash_audit: bool = False


class SelfIntegrityMonitor:
    def __init__(self, host_id: str, targets: Iterable[Path], *, max_files: int = 1_000, max_file_bytes: int = 8 * 1024 * 1024, full_hash_interval_seconds: float = 300.0, monotonic: Callable[[], float] = time.monotonic) -> None:
        if max_files <= 0 or max_file_bytes <= 0:
            raise ValueError("integrity limits must be positive")
        if full_hash_interval_seconds <= 0:
            raise ValueError("full_hash_interval_seconds must be positive")
        self.host_id = host_id
        self.targets = tuple(dict.fromkeys(Path(item).expanduser().resolve() for item in targets))
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.full_hash_interval_seconds = float(full_hash_interval_seconds)
        self._monotonic = monotonic
        self._last_full_hash_at: float | None = None

    @classmethod
    def default(cls, host_id: str, *, package_root: Path, config_path: Path | None = None, model_path: Path | None = None, extra_paths: Iterable[Path] = ()) -> "SelfIntegrityMonitor":
        targets: list[Path] = [package_root]
        if config_path is not None:
            targets.append(config_path)
        if model_path is not None:
            targets.append(model_path)
        user_unit = Path("~/.config/systemd/user/quietward.service").expanduser()
        if user_unit.exists():
            targets.append(user_unit)
        targets.extend(extra_paths)
        return cls(host_id, targets)

    def _files(self) -> tuple[list[Path], bool]:
        files: list[Path] = []
        for target in self.targets:
            if target.is_file():
                files.append(target)
            elif target.is_dir():
                try:
                    files.extend(path for path in target.rglob("*") if path.is_file() and (path.suffix in {".py", ".json", ".service"} or path.name == "config.json"))
                except OSError:
                    continue
            if len(files) >= self.max_files:
                return sorted(set(files), key=str)[: self.max_files], True
        return sorted(set(files), key=str), False

    @staticmethod
    def _semantic(entry: dict[str, object] | None) -> tuple[object, object, object] | None:
        if entry is None:
            return None
        return entry.get("sha256"), entry.get("mode"), entry.get("size")

    def scan(self, previous: dict[str, dict[str, object]] | None = None, *, observed_at: datetime | None = None) -> IntegrityScan:
        timestamp = observed_at or datetime.now(timezone.utc)
        now = self._monotonic()
        full_audit = previous is None or self._last_full_hash_at is None or now - self._last_full_hash_at >= self.full_hash_interval_seconds
        files, truncated = self._files()
        manifest: dict[str, dict[str, object]] = {}
        files_hashed = 0
        hashes_reused = 0
        for path in files:
            key = str(path)
            prior = previous.get(key) if previous is not None else None
            metadata = _file_metadata(path, self.max_file_bytes)
            if metadata is None:
                continue
            mode, size, mtime_ns, ctime_ns = metadata
            sample_sha256 = _sample_file(path, self.max_file_bytes)
            can_reuse = os.name != "nt" and not full_audit and prior is not None and prior.get("sha256") is not None and sample_sha256 is not None and prior.get("sample_sha256") == sample_sha256 and prior.get("mode") == mode and prior.get("size") == size and prior.get("mtime_ns") == mtime_ns and prior.get("ctime_ns") == ctime_ns
            if can_reuse:
                manifest[key] = {"sha256": prior.get("sha256"), "sample_sha256": sample_sha256, "mode": mode, "size": size, "mtime_ns": mtime_ns, "ctime_ns": ctime_ns}
                hashes_reused += 1
                continue
            value = _hash_file(path, self.max_file_bytes)
            if value is None:
                continue
            digest, hashed_mode, hashed_size, hashed_mtime_ns, hashed_ctime_ns = value
            manifest[key] = {"sha256": digest, "sample_sha256": sample_sha256, "mode": hashed_mode, "size": hashed_size, "mtime_ns": hashed_mtime_ns, "ctime_ns": hashed_ctime_ns}
            files_hashed += 1
        if full_audit:
            self._last_full_hash_at = now
        if previous is None:
            return IntegrityScan(manifest, (), truncated, files_hashed, hashes_reused, full_audit)
        events: list[SecurityEvent] = []
        all_paths = sorted(set(previous) | set(manifest))
        for path in all_paths[: self.max_files]:
            before = previous.get(path)
            after = manifest.get(path)
            if self._semantic(before) == self._semantic(after):
                continue
            change = "created" if before is None else "removed" if after is None else "modified"
            digest = hashlib.sha256(f"{self.host_id}|integrity|{path}|{json.dumps(before, sort_keys=True)}|{json.dumps(after, sort_keys=True)}|{timestamp.isoformat()}".encode()).hexdigest()[:20]
            events.append(SecurityEvent(
                event_id="qwd-" + digest,
                observed_at=timestamp,
                host_id=self.host_id,
                source="quietward_self_integrity",
                kind=EventKind.SELF_INTEGRITY_CHANGE,
                subject=path,
                attributes={"change_type": change, "previous_sha256": before.get("sha256") if before else None, "current_sha256": after.get("sha256") if after else None, "previous_mode": before.get("mode") if before else None, "current_mode": after.get("mode") if after else None, "persistence_indicator": True, "privileged_context": True, "baseline_deviation": 1.0, "raw_content_persisted": False, "authoritative_rule_match": True},
                confidence=1.0,
            ))
        return IntegrityScan(manifest, tuple(events), truncated, files_hashed, hashes_reused, full_audit)
