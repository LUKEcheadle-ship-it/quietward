from __future__ import annotations

from dataclasses import replace
from typing import Iterable

from ..contracts import SecurityEvent


def retag_event_sources(
    events: Iterable[SecurityEvent],
    *,
    old_prefix: str,
    new_prefix: str,
) -> tuple[SecurityEvent, ...]:
    result: list[SecurityEvent] = []
    for event in events:
        source = event.source
        if source.startswith(old_prefix):
            source = new_prefix + source[len(old_prefix):]
        result.append(replace(event, source=source))
    return tuple(result)
