from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from ..contracts import SecurityEvent


def event_id(scanner: str, host_id: str, subject: str, discriminator: str) -> str:
    payload = f"{scanner}|{host_id}|{subject}|{discriminator}".encode("utf-8", errors="replace")
    return "fse-" + hashlib.sha256(payload).hexdigest()[:20]


def observed_time(value: datetime | None) -> datetime:
    return value or datetime.now(timezone.utc)


def require_host_id(host_id: str) -> str:
    normalized = host_id.strip()
    if not normalized:
        raise ValueError("host_id must not be empty")
    return normalized


def bounded(value: object, limit: int = 300) -> str:
    return " ".join(str(value or "").replace("\x00", "").split())[:limit]


def safe_target(value: str) -> str:
    if not value.strip():
        return "unknown-target"
    path = Path(value)
    return str(path)[:1000]


def sort_events(events: list[SecurityEvent]) -> list[SecurityEvent]:
    return sorted(events, key=lambda item: (item.subject, item.kind.value, item.event_id))
