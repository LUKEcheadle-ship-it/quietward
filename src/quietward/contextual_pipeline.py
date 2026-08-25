from __future__ import annotations

from typing import Iterable

from .contracts import SecurityEvent
from .temporal_context import TemporalContextWindow


class ContextualPipeline:
    """Wrap an analysis pipeline with commit-on-success multi-cycle context.

    ``analyze`` may read prior committed context but never mutates the window.
    The service calls ``commit_pending`` only after the observation cycle has
    successfully persisted. Failed cycles call ``discard_pending`` so undurable
    evidence cannot influence future correlation.
    """

    def __init__(
        self,
        inner,
        *,
        window: TemporalContextWindow | None = None,
    ) -> None:
        self.inner = inner
        self.window = window or TemporalContextWindow()
        self._pending: tuple[SecurityEvent, ...] = ()

    def analyze(self, events: list[SecurityEvent]):
        if self._pending:
            raise RuntimeError("temporal context pipeline has uncommitted events")
        original = tuple(events)
        contextual = self.window.enrich(original)
        self._pending = original
        return self.inner.analyze(contextual)

    def commit_pending(self) -> None:
        if self._pending:
            self.window.observe(self._pending)
        self._pending = ()

    def discard_pending(self) -> None:
        self._pending = ()

    def state(self) -> dict[str, object]:
        value = dict(self.window.state())
        value["pending_events"] = len(self._pending)
        value["actions_executed"] = 0
        return value
