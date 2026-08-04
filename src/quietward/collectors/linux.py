from __future__ import annotations

from dataclasses import replace

from .debian import DebianCollectorConfig, DebianReadOnlyCollector
from .models import CollectionBatch, CollectorSnapshot
from .retag import retag_event_sources
from ..platforms import PlatformInfo, detect_platform


LinuxCollectorConfig = DebianCollectorConfig


class LinuxReadOnlyCollector(DebianReadOnlyCollector):
    """Capability-tolerant Linux collector using the established read-only lane.

    Debian remains the fully qualified target. Other systemd Linux
    distributions use the same normalized commands and degrade unavailable
    optional capabilities into collector warnings.
    """

    def __init__(
        self,
        config: LinuxCollectorConfig | None = None,
        runner=None,
        host_id: str | None = None,
        platform_info: PlatformInfo | None = None,
    ) -> None:
        self.platform_info = platform_info or detect_platform()
        super().__init__(config=config, runner=runner, host_id=host_id)

    def collect(
        self,
        previous: CollectorSnapshot | None = None,
    ) -> CollectionBatch:
        batch = super().collect(previous)
        distro = self.platform_info.distro_id or "unknown"
        snapshot = replace(
            batch.snapshot,
            collector_version=f"linux-read-only-v1:{distro}",
        )
        return CollectionBatch(
            snapshot,
            retag_event_sources(
                batch.events,
                old_prefix="debian_",
                new_prefix="linux_",
            ),
        )
