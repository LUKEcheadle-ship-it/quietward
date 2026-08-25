from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from .contracts import SecurityEvent
from .correlation import _actor_keys


@dataclass(frozen=True, slots=True)
class TemporalContextState:
    retained_events: int
    max_events: int
    window_seconds: float

    def to_dict(self) -> dict[str, object]:
        return {
            "retained_events": self.retained_events,
            "max_events": self.max_events,
            "window_seconds": self.window_seconds,
            "actions_executed": 0,
        }


def _split_actor_keys(event: SecurityEvent) -> tuple[set[str], set[str]]:
    values = set(_actor_keys(event))
    return (
        {item for item in values if item.startswith("pid:")},
        {item for item in values if item.startswith("name:")},
    )


def _cross_cycle_actor_match(current: SecurityEvent, previous: SecurityEvent) -> bool:
    current_pids, current_names = _split_actor_keys(current)
    previous_pids, previous_names = _split_actor_keys(previous)
    name_match = bool(current_names & previous_names)
    if not name_match:
        return False
    if current_pids and previous_pids:
        return bool(current_pids & previous_pids)
    return True


class TemporalContextWindow:
    """Bounded indexed in-memory context for linking evidence across cycles."""

    def __init__(
        self,
        *,
        window_seconds: float = 300.0,
        max_events: int = 512,
        max_related_per_event: int = 8,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("temporal context window_seconds must be positive")
        if max_events <= 0 or max_related_per_event <= 0:
            raise ValueError("temporal context limits must be positive")
        self.window_seconds = float(window_seconds)
        self.max_events = int(max_events)
        self.max_related_per_event = int(max_related_per_event)
        self._events: deque[SecurityEvent] = deque(maxlen=self.max_events)

    def _prune(self, reference: datetime) -> None:
        if reference.tzinfo is None:
            raise ValueError("temporal context timestamps must be timezone-aware")
        threshold = reference.astimezone(timezone.utc).timestamp() - self.window_seconds
        while self._events:
            oldest = self._events[0].observed_at.astimezone(timezone.utc).timestamp()
            if oldest >= threshold:
                break
            self._events.popleft()

    @staticmethod
    def _indexes(prior: tuple[SecurityEvent, ...]):
        by_subject: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        by_name: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        for event in prior:
            by_subject[(event.host_id, event.subject)].append(event)
            _, names = _split_actor_keys(event)
            for name in names:
                by_name[(event.host_id, name)].append(event)
        return by_subject, by_name

    def enrich(self, events: Iterable[SecurityEvent]) -> list[SecurityEvent]:
        current = list(events)
        if not current:
            return []
        reference = max(event.observed_at for event in current)
        self._prune(reference)
        prior = tuple(self._events)
        by_subject, by_name = self._indexes(prior)
        enriched: list[SecurityEvent] = []

        for event in current:
            candidate_map: dict[str, SecurityEvent] = {}
            for previous in by_subject.get((event.host_id, event.subject), ()):
                candidate_map[previous.event_id] = previous
            _, names = _split_actor_keys(event)
            for name in names:
                for previous in by_name.get((event.host_id, name), ()):
                    candidate_map[previous.event_id] = previous

            candidates: list[tuple[float, SecurityEvent, bool, bool]] = []
            event_time = event.observed_at.astimezone(timezone.utc)
            for previous in candidate_map.values():
                if previous.kind == event.kind:
                    continue
                age = (event_time - previous.observed_at.astimezone(timezone.utc)).total_seconds()
                if age < 0 or age > self.window_seconds:
                    continue
                actor_match = _cross_cycle_actor_match(event, previous)
                subject_match = previous.subject == event.subject
                if not actor_match and not subject_match:
                    continue
                candidates.append((age, previous, actor_match, subject_match))

            candidates.sort(key=lambda item: (item[0], item[1].event_id))
            selected = candidates[: self.max_related_per_event]
            if not selected:
                enriched.append(event)
                continue

            related = [item[1] for item in selected]
            attributes = dict(event.attributes)
            attributes.update(
                {
                    "temporal_context_count": len(related),
                    "temporal_context_distinct_kinds": len({item.kind.value for item in related}),
                    "temporal_context_actor_match": any(item[2] for item in selected),
                    "temporal_context_subject_match": any(item[3] for item in selected),
                    "temporal_context_event_ids": [item.event_id for item in related],
                    "temporal_context_sources": sorted({item.source for item in related})[:8],
                    "temporal_context_max_age_seconds": round(max(item[0] for item in selected), 3),
                    "temporal_context_persisted_history_unchanged": True,
                }
            )
            enriched.append(
                SecurityEvent(
                    event_id=event.event_id,
                    observed_at=event.observed_at,
                    host_id=event.host_id,
                    source=event.source,
                    kind=event.kind,
                    subject=event.subject,
                    attributes=attributes,
                    confidence=event.confidence,
                )
            )
        return enriched

    def observe(self, events: Iterable[SecurityEvent]) -> None:
        values = sorted(list(events), key=lambda item: (item.observed_at, item.event_id))
        if not values:
            return
        self._prune(max(item.observed_at for item in values))
        for event in values:
            self._events.append(event)

    def state(self) -> dict[str, object]:
        return TemporalContextState(
            retained_events=len(self._events),
            max_events=self.max_events,
            window_seconds=self.window_seconds,
        ).to_dict()
