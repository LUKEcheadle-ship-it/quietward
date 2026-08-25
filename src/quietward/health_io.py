from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any


class HealthDurabilityPolicy:
    def __init__(self, checkpoint_seconds: float = 300.0) -> None:
        if checkpoint_seconds <= 0:
            raise ValueError("health checkpoint_seconds must be positive")
        self.checkpoint_seconds = float(checkpoint_seconds)
        self._last_durable_at: float | None = None
        self._last_material_key: tuple[object, ...] | None = None

    def requires_durable(self, *, status: str, persistence_mode: str | None, material_key: tuple[object, ...], now: float) -> bool:
        if status != "healthy":
            return True
        if persistence_mode != "volatile":
            return True
        if self._last_durable_at is None:
            return True
        if material_key != self._last_material_key:
            return True
        return now - self._last_durable_at >= self.checkpoint_seconds

    def mark_durable(self, material_key: tuple[object, ...], *, now: float) -> None:
        self._last_durable_at = float(now)
        self._last_material_key = tuple(material_key)

    def state(self, *, now: float) -> dict[str, object]:
        return {
            "checkpoint_seconds": self.checkpoint_seconds,
            "seconds_since_durable": round(max(0.0, now - self._last_durable_at), 3) if self._last_durable_at is not None else None,
            "has_material_baseline": self._last_material_key is not None,
            "actions_executed": 0,
        }


def atomic_live_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    temporary = path.with_name(f".{path.name}.live-{os.getpid()}-{threading.get_ident()}-{time.time_ns()}")
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
                raise OSError("short live health-file write")
            offset += written
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        try:
            path.chmod(0o600)
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
