from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping

from ..contracts import EventKind, SecurityEvent
from .models import ProcessRecord


def _records(text: str) -> list[dict[str, Any]]:
    stripped = text.strip()
    if not stripped:
        return []
    value = json.loads(stripped)
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if not isinstance(value, list):
        raise ValueError("Windows socket output must be a JSON object or array")
    return [dict(item) for item in value if isinstance(item, dict)]


def _integer(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _string(value: object) -> str:
    return str(value or "").strip()


def _local_scope(address: str) -> str:
    value = address.strip()
    if value in {"0.0.0.0", "::", "*"}:
        return "*"
    try:
        parsed = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return "unknown-interface"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link-local-interface"
    if parsed.is_private:
        return "private-interface"
    return "public-interface"


@dataclass(frozen=True, slots=True)
class ListenerAttribution:
    protocol: str
    local_address: str
    port: int
    process_name: str | None
    owning_pid: int | None
    executable: str | None
    command_name: str | None
    user_identity_hash: str | None
    suspicious_markers: tuple[str, ...]
    privileged_context: bool
    confidence: str

    @property
    def key(self) -> tuple[str, str, int, str | None]:
        return self.protocol, self.local_address, self.port, self.process_name

    def event_attributes(self) -> dict[str, object]:
        return {
            "owner_pid": self.owning_pid,
            "owner_executable": self.executable,
            "owner_command_name": self.command_name,
            "owner_user_identity_hash": self.user_identity_hash,
            "owner_suspicious_markers": list(self.suspicious_markers),
            "owner_privileged_context": self.privileged_context,
            "process_attribution": self.confidence,
            "raw_command_line_persisted": False,
            "raw_username_persisted": False,
        }


def build_listener_attribution(
    socket_output: str,
    processes: Iterable[ProcessRecord],
) -> dict[tuple[str, str, int, str | None], ListenerAttribution]:
    by_pid = {process.pid: process for process in processes if process.pid > 0}
    result: dict[tuple[str, str, int, str | None], ListenerAttribution] = {}
    for row in _records(socket_output):
        port = _integer(row.get("LocalPort"), -1)
        if not 0 <= port <= 65535:
            continue
        protocol = (_string(row.get("Protocol")) or "tcp").casefold()
        local_address = _local_scope(_string(row.get("LocalAddress")))
        process_name = _string(row.get("ProcessName")) or None
        raw_pid = _integer(row.get("OwningProcess"), 0)
        owning_pid = raw_pid if raw_pid > 0 else None
        process = by_pid.get(raw_pid) if raw_pid > 0 else None
        attribution = ListenerAttribution(
            protocol=protocol,
            local_address=local_address,
            port=port,
            process_name=process_name,
            owning_pid=owning_pid,
            executable=process.executable if process is not None else None,
            command_name=process.command_name if process is not None else None,
            user_identity_hash=process.user if process is not None and process.user != "unavailable" else None,
            suspicious_markers=process.suspicious_markers if process is not None else (),
            privileged_context=process.privileged_context if process is not None else False,
            confidence=("pid_inventory_match" if process is not None else "socket_pid_only" if owning_pid is not None else "process_name_only" if process_name is not None else "unattributed"),
        )
        result[attribution.key] = attribution
    return result


def enrich_listener_events(
    events: Iterable[SecurityEvent],
    attributions: Mapping[tuple[str, str, int, str | None], ListenerAttribution],
) -> tuple[SecurityEvent, ...]:
    result: list[SecurityEvent] = []
    for event in events:
        if event.kind != EventKind.NEW_LISTENING_PORT:
            result.append(event)
            continue
        attributes = dict(event.attributes)
        key = (
            str(attributes.get("protocol") or "").casefold(),
            str(attributes.get("local_address") or ""),
            _integer(attributes.get("port"), -1),
            str(attributes["process_name"]) if attributes.get("process_name") is not None else None,
        )
        attribution = attributions.get(key)
        if attribution is None:
            attributes["process_attribution"] = "unattributed"
            result.append(replace(event, attributes=attributes))
            continue
        attributes.update(attribution.event_attributes())
        attributes["privileged_context"] = bool(attributes.get("privileged_context") or attribution.privileged_context)
        confidence = max(event.confidence, 0.9 if attribution.confidence == "pid_inventory_match" else event.confidence)
        result.append(replace(event, attributes=attributes, confidence=confidence))
    return tuple(result)
