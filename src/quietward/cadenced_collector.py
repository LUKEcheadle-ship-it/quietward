from __future__ import annotations

from collections import deque
from dataclasses import is_dataclass, replace
from typing import Iterable

from .collectors.models import CollectionBatch, CollectorSnapshot


_CONFIG_FLAGS = {
    "processes": ("include_processes",),
    "listening_sockets": ("include_sockets",),
    "outbound_connections": ("include_connections",),
    "authentication": ("include_auth_events", "include_auth_journal"),
    "docker": ("include_docker",),
    "persistence": ("include_persistence",),
}

_SNAPSHOT_FIELDS = {
    "processes": "processes",
    "listening_sockets": "sockets",
    "outbound_connections": "connections",
    "docker": "containers",
    "persistence": "persistence",
    "sensitive_files": "files",
}

_ALL_DOMAINS = frozenset({*_CONFIG_FLAGS, "sensitive_files"})
_STANDARD_DOMAINS = frozenset({"persistence", "docker"})
_AUTH_SOURCES = frozenset(
    {
        "journald_ssh_read_only",
        "windows_security_log_read_only",
        "debian_auth_journal",
        "windows_security_log",
    }
)


class CadencedCollectorAdapter:
    """Run only due collector domains while preserving skipped snapshot state."""

    def __init__(self, collector, *, max_recent_auth_event_ids: int = 4096) -> None:
        config = getattr(collector, "config", None)
        if config is None or not is_dataclass(config):
            raise TypeError("cadenced collector requires a dataclass collector config")
        if max_recent_auth_event_ids <= 0:
            raise ValueError("max_recent_auth_event_ids must be positive")
        self.collector = collector
        self.host_id = collector.host_id
        self.config = config
        self.runner = getattr(collector, "runner", None)
        groups = tuple(getattr(collector, "cadence_coalesce_domains", ()))
        self._coalesce_groups = tuple(frozenset(group) for group in groups)
        self._requested_domains: frozenset[str] = _ALL_DOMAINS
        self.last_active_domains: frozenset[str] = self._requested_domains
        self.max_recent_auth_event_ids = int(max_recent_auth_event_ids)
        self._recent_auth_ids: deque[str] = deque()
        self._recent_auth_set: set[str] = set()

    def set_active_domains(self, domains: Iterable[str]) -> frozenset[str]:
        active = {str(item) for item in domains}
        for group in self._coalesce_groups:
            if active & group:
                active.update(group)
        self._requested_domains = frozenset(active)
        self.last_active_domains = self._requested_domains
        return self.last_active_domains

    def _cadenced_config(self):
        changes: dict[str, object] = {}
        config = self.config
        for domain_name, flags in _CONFIG_FLAGS.items():
            enabled = domain_name in self._requested_domains
            for flag in flags:
                if hasattr(config, flag):
                    original = bool(getattr(config, flag))
                    changes[flag] = original and enabled
        if hasattr(config, "sensitive_files") and "sensitive_files" not in self._requested_domains:
            changes["sensitive_files"] = ()
        if hasattr(config, "refresh_slow_context"):
            changes["refresh_slow_context"] = bool(
                self._requested_domains & _STANDARD_DOMAINS
            )
        return replace(config, **changes)

    @staticmethod
    def _project_previous(
        previous: CollectorSnapshot | None,
        active: frozenset[str],
    ) -> CollectorSnapshot | None:
        if previous is None:
            return None
        changes: dict[str, object] = {"errors": ()}
        for domain_name, field_name in _SNAPSHOT_FIELDS.items():
            if domain_name not in active:
                changes[field_name] = ()
        return replace(previous, **changes)

    @staticmethod
    def _merge_snapshot(
        current: CollectorSnapshot,
        previous: CollectorSnapshot | None,
        active: frozenset[str],
    ) -> CollectorSnapshot:
        if previous is None:
            return current
        changes: dict[str, object] = {}
        for domain_name, field_name in _SNAPSHOT_FIELDS.items():
            if domain_name not in active:
                changes[field_name] = getattr(previous, field_name)
        return replace(current, **changes) if changes else current

    def _remember_auth_id(self, event_id: str) -> None:
        if event_id in self._recent_auth_set:
            return
        self._recent_auth_ids.append(event_id)
        self._recent_auth_set.add(event_id)
        while len(self._recent_auth_ids) > self.max_recent_auth_event_ids:
            removed = self._recent_auth_ids.popleft()
            self._recent_auth_set.discard(removed)

    def _deduplicate_rolling_auth(self, events):
        values = []
        for event in events:
            is_auth = (
                getattr(event.kind, "value", str(event.kind)) == "auth_failure"
                or str(event.source).casefold() in _AUTH_SOURCES
            )
            if not is_auth:
                values.append(event)
                continue
            if event.event_id in self._recent_auth_set:
                continue
            self._remember_auth_id(event.event_id)
            values.append(event)
        return tuple(values)

    def collect(self, previous: CollectorSnapshot | None = None) -> CollectionBatch:
        active = self._requested_domains
        original_config = self.collector.config
        projected = self._project_previous(previous, active)
        self.collector.config = self._cadenced_config()
        try:
            batch = self.collector.collect(projected)
        finally:
            self.collector.config = original_config
        merged = self._merge_snapshot(batch.snapshot, previous, active)
        return CollectionBatch(
            merged,
            self._deduplicate_rolling_auth(batch.events),
        )
