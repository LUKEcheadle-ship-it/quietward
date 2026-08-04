from __future__ import annotations

import re
from datetime import datetime

from ..contracts import EventKind, SecurityEvent
from .common import bounded, event_id, observed_time, require_host_id, safe_target, sort_events

_FOUND = re.compile(r"^(?P<target>.+):\s+(?P<signature>.+)\s+FOUND$")


def parse_clamav_output(
    text: str,
    host_id: str,
    *,
    observed_at: datetime | None = None,
    scanner_exit_code: int | None = None,
) -> list[SecurityEvent]:
    """Parse positive ClamAV report lines. Summary and clean lines are ignored."""
    host = require_host_id(host_id)
    timestamp = observed_time(observed_at)
    events: list[SecurityEvent] = []
    for line in text.splitlines():
        match = _FOUND.match(line.strip())
        if not match:
            continue
        target = safe_target(match.group("target"))
        signature = bounded(match.group("signature"), 300)
        if not signature:
            continue
        events.append(
            SecurityEvent(
                event_id=event_id("clamav", host, target, signature),
                observed_at=timestamp,
                host_id=host,
                source="clamav_report_adapter",
                kind=EventKind.MALWARE_SIGNATURE,
                subject=target,
                attributes={
                    "signature": signature,
                    "authoritative_scanner_detection": True,
                    "scanner_exit_code": scanner_exit_code,
                    "raw_scanner_output_persisted": False,
                },
                confidence=1.0,
            )
        )
    return sort_events(events)
