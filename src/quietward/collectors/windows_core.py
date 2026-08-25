from __future__ import annotations

import json
from dataclasses import dataclass

from ..privacy_identity import PrivacyIdentity
from .models import DefenderStatus, PersistenceRecord, ProcessRecord, SocketRecord
from .windows_attribution import ListenerAttribution, build_listener_attribution
from .windows_parsers import (
    parse_windows_defender,
    parse_windows_persistence,
    parse_windows_processes,
    parse_windows_sockets,
)


@dataclass(frozen=True, slots=True)
class WindowsCoreInventory:
    defender: DefenderStatus | None
    processes: tuple[ProcessRecord, ...]
    sockets: tuple[SocketRecord, ...]
    persistence: tuple[PersistenceRecord, ...]
    listener_attribution: dict[tuple[str, str, int, str | None], ListenerAttribution]
    defender_ok: bool
    processes_ok: bool
    sockets_ok: bool
    persistence_ok: bool

    @property
    def complete(self) -> bool:
        return self.processes_ok and self.sockets_ok and self.persistence_ok


def _json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def parse_windows_core_inventory(
    text: str,
    privacy_identity: PrivacyIdentity | None,
    *,
    max_persistence_entries: int = 2000,
) -> WindowsCoreInventory:
    raw = json.loads(text.strip())
    if not isinstance(raw, dict):
        raise ValueError("Windows core inventory must be a JSON object")

    defender_ok = raw.get("DefenderOk") is True
    processes_ok = raw.get("ProcessesOk") is True
    sockets_ok = raw.get("SocketsOk") is True
    persistence_ok = raw.get("PersistenceOk") is True

    defender = (
        parse_windows_defender(_json(raw.get("Defender")))
        if defender_ok and raw.get("Defender") is not None
        else None
    )
    processes = (
        parse_windows_processes(_json(raw.get("Processes") or []), privacy_identity)
        if processes_ok
        else ()
    )
    sockets_raw = raw.get("Sockets") or []
    sockets = parse_windows_sockets(_json(sockets_raw)) if sockets_ok else ()
    persistence = (
        parse_windows_persistence(
            _json(raw.get("Persistence") or []),
            privacy_identity,
            max_persistence_entries,
        )
        if persistence_ok and privacy_identity is not None
        else ()
    )
    listener_attribution = (
        build_listener_attribution(_json(sockets_raw), processes)
        if sockets_ok
        else {}
    )
    return WindowsCoreInventory(
        defender=defender,
        processes=processes,
        sockets=sockets,
        persistence=persistence,
        listener_attribution=listener_attribution,
        defender_ok=defender_ok,
        processes_ok=processes_ok,
        sockets_ok=sockets_ok,
        persistence_ok=persistence_ok,
    )
