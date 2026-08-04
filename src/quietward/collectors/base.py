from __future__ import annotations

from typing import Protocol

from .models import CollectionBatch, CollectorSnapshot


class ReadOnlyCollector(Protocol):
    host_id: str

    def collect(
        self,
        previous: CollectorSnapshot | None = None,
    ) -> CollectionBatch: ...
