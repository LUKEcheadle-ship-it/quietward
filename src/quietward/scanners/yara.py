from __future__ import annotations

import re
from datetime import datetime

from ..contracts import EventKind, SecurityEvent
from .common import bounded, event_id, observed_time, require_host_id, safe_target, sort_events

_RULE = re.compile(r"^(?P<rule>[A-Za-z_][A-Za-z0-9_]*)\b")


def parse_yara_output(
    text: str,
    host_id: str,
    target: str,
    *,
    observed_at: datetime | None = None,
) -> list[SecurityEvent]:
    """Parse default YARA match lines while intentionally discarding string-match output."""
    host = require_host_id(host_id)
    subject = safe_target(target)
    timestamp = observed_time(observed_at)
    events: list[SecurityEvent] = []
    seen: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("0x"):
            continue
        match = _RULE.match(stripped)
        if not match:
            continue
        rule = bounded(match.group("rule"), 200)
        if not rule or rule in seen:
            continue
        seen.add(rule)
        events.append(
            SecurityEvent(
                event_id=event_id("yara", host, subject, rule),
                observed_at=timestamp,
                host_id=host,
                source="yara_report_adapter",
                kind=EventKind.YARA_MATCH,
                subject=subject,
                attributes={
                    "rule": rule,
                    "authoritative_rule_match": True,
                    "raw_string_matches_persisted": False,
                    "raw_scanner_output_persisted": False,
                },
                confidence=1.0,
            )
        )
    return sort_events(events)
