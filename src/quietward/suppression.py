from __future__ import annotations

from collections.abc import Iterable

from .contracts import EventKind, SecurityEvent


_BYPASS_MARKERS = {
    "credential_spray",
    "credential_dumping",
    "credential_theft",
    "reverse_shell",
    "web_shell",
    "process_injection",
    "document_spawned_interpreter",
    "server_spawned_suspicious_shell",
    "web_server_spawned_suspicious_shell",
    "ransomware_recovery_inhibition",
    "event_log_clearing",
    "dangerous_container_config",
    "docker_socket_mount",
    "host_root_mount",
}


def _markers(event: SecurityEvent) -> set[str]:
    result: set[str] = set()
    for key in (
        "suspicious_markers",
        "risk_markers",
        "security_markers",
        "owner_suspicious_markers",
    ):
        raw = event.attributes.get(key)
        if raw is None:
            continue
        values: Iterable[object] = (raw,) if isinstance(raw, str) else raw
        try:
            for value in values:
                marker = str(value).strip().casefold().replace("-", "_").replace(" ", "_")
                if marker:
                    result.add(marker)
        except TypeError:
            continue
    return result


def event_bypasses_suppression(event: SecurityEvent) -> bool:
    if event.kind in {
        EventKind.MALWARE_SIGNATURE,
        EventKind.YARA_MATCH,
        EventKind.CONTAINER_ESCAPE_INDICATOR,
        EventKind.EVIDENCE_INTEGRITY_FAILURE,
    }:
        return True
    if _markers(event) & _BYPASS_MARKERS:
        return True
    return bool(
        event.kind is EventKind.AUTH_FAILURE
        and event.attributes.get("credential_spray_candidate") is True
    )


def partition_for_suppression(
    events: Iterable[SecurityEvent],
) -> tuple[list[SecurityEvent], list[SecurityEvent]]:
    bypass: list[SecurityEvent] = []
    eligible: list[SecurityEvent] = []
    for event in events:
        (bypass if event_bypasses_suppression(event) else eligible).append(event)
    return bypass, eligible
