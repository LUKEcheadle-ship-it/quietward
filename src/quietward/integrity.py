from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .contracts import EventKind, SecurityEvent


def _hash_file(path: Path, max_bytes: int) -> tuple[str, int, int] | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > max_bytes:
        return None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            hasher = hashlib.sha256()
            while chunk := os.read(descriptor, 128 * 1024):
                hasher.update(chunk)
        finally:
            os.close(descriptor)
    except OSError:
        return None
    return hasher.hexdigest(), stat.S_IMODE(info.st_mode), info.st_size


@dataclass(frozen=True, slots=True)
class IntegrityScan:
    manifest: dict[str, dict[str, object]]
    events: tuple[SecurityEvent, ...]
    truncated: bool = False


class SelfIntegrityMonitor:
    def __init__(self, host_id: str, targets: Iterable[Path], *, max_files: int = 1_000, max_file_bytes: int = 8 * 1024 * 1024) -> None:
        if max_files <= 0 or max_file_bytes <= 0:
            raise ValueError("integrity limits must be positive")
        self.host_id = host_id
        self.targets = tuple(dict.fromkeys(Path(item).expanduser().resolve() for item in targets))
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes

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

    def scan(self, previous: dict[str, dict[str, object]] | None = None, *, observed_at: datetime | None = None) -> IntegrityScan:
        timestamp = observed_at or datetime.now(timezone.utc)
        files, truncated = self._files()
        manifest: dict[str, dict[str, object]] = {}
        for path in files:
            value = _hash_file(path, self.max_file_bytes)
            if value is None:
                continue
            digest, mode, size = value
            manifest[str(path)] = {"sha256": digest, "mode": mode, "size": size}
        if previous is None:
            return IntegrityScan(manifest, (), truncated)
        events: list[SecurityEvent] = []
        all_paths = sorted(set(previous) | set(manifest))
        for path in all_paths[: self.max_files]:
            before = previous.get(path)
            after = manifest.get(path)
            if before == after:
                continue
            change = "created" if before is None else "removed" if after is None else "modified"
            digest = hashlib.sha256(f"{self.host_id}|integrity|{path}|{json.dumps(before,sort_keys=True)}|{json.dumps(after,sort_keys=True)}|{timestamp.isoformat()}".encode()).hexdigest()[:20]
            events.append(SecurityEvent(
                event_id="qwd-" + digest,
                observed_at=timestamp,
                host_id=self.host_id,
                source="quietward_self_integrity",
                kind=EventKind.SELF_INTEGRITY_CHANGE,
                subject=path,
                attributes={
                    "change_type": change,
                    "previous_sha256": before.get("sha256") if before else None,
                    "current_sha256": after.get("sha256") if after else None,
                    "previous_mode": before.get("mode") if before else None,
                    "current_mode": after.get("mode") if after else None,
                    "persistence_indicator": True,
                    "privileged_context": True,
                    "baseline_deviation": 1.0,
                    "raw_content_persisted": False,
                    "authoritative_rule_match": True,
                },
                confidence=1.0,
            ))
        return IntegrityScan(manifest, tuple(events), truncated)
