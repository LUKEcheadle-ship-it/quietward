from __future__ import annotations

import re
from datetime import datetime

from ..contracts import EventKind, SecurityEvent
from .common import bounded, event_id, observed_time, require_host_id, sort_events

_CVE = re.compile(r"^(?P<cve>CVE-\d{4}-\d+)\s+(?P<packages>.+)$", re.IGNORECASE)
_PACKAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.:-]*$")


def parse_debsecan_simple(
    text: str,
    host_id: str,
    *,
    observed_at: datetime | None = None,
    suite: str | None = None,
) -> list[SecurityEvent]:
    """Parse `debsecan --format simple` vulnerability/package pairs."""
    host = require_host_id(host_id)
    timestamp = observed_time(observed_at)
    events: list[SecurityEvent] = []
    for line in text.splitlines():
        match = _CVE.match(line.strip())
        if not match:
            continue
        cve = match.group("cve").upper()
        packages = [token for token in match.group("packages").split() if _PACKAGE.match(token)]
        for package in sorted(set(packages)):
            subject = f"package:{bounded(package, 200)}"
            events.append(
                SecurityEvent(
                    event_id=event_id("debsecan", host, subject, cve),
                    observed_at=timestamp,
                    host_id=host,
                    source="debsecan_simple_adapter",
                    kind=EventKind.PACKAGE_VULNERABILITY,
                    subject=subject,
                    attributes={
                        "vulnerability_id": cve,
                        "package": bounded(package, 200),
                        "suite": bounded(suite, 80) or None,
                        "cvss": 0.0,
                        "severity": "UNKNOWN",
                        "source_package_mapping_caveat": True,
                        "raw_report_persisted": False,
                    },
                    confidence=0.8,
                )
            )
    return sort_events(events)
