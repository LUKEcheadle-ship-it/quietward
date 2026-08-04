from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Iterable

from ..contracts import EventKind, SecurityEvent
from .models import CollectorSnapshot, ConnectionRecord, ContainerRecord, FileRecord, PersistenceRecord, ProcessRecord, SocketRecord


def _event_id(*parts: object) -> str:
    payload = "|".join(str(part) for part in parts).encode("utf-8", errors="replace")
    return "fse-" + hashlib.sha256(payload).hexdigest()[:20]


def _changed_fields(before: FileRecord, after: FileRecord) -> tuple[str, ...]:
    return tuple(name for name in ("exists", "file_type", "mode", "size", "mtime_ns", "sha256") if getattr(before, name) != getattr(after, name))


def _new_items(current: Iterable, previous: Iterable, key) -> list:
    previous_keys = {key(item) for item in previous}
    return [item for item in current if key(item) not in previous_keys]


def _persistence_event(current: CollectorSnapshot, record: PersistenceRecord, observed_at: datetime, *, change_type: str, previous_fingerprint: str | None = None) -> SecurityEvent:
    kind = EventKind.ACCOUNT_CHANGE if record.category in {"account", "group"} else EventKind.PERSISTENCE_CHANGE
    privileged = bool(set(record.risk_markers) & {"uid_zero_alias", "privileged_group_membership", "root_authorized_keys", "privilege_configuration"})
    return SecurityEvent(
        event_id=_event_id(current.host_id, "persistence", record.identity, record.fingerprint, observed_at.isoformat()),
        observed_at=observed_at,
        host_id=current.host_id,
        source="debian_persistence_snapshot",
        kind=kind,
        subject=record.subject,
        attributes={"category": record.category, "change_type": change_type, "previous_fingerprint": previous_fingerprint, "current_fingerprint": record.fingerprint, "risk_markers": list(record.risk_markers), "metadata": record.metadata, "persistence_indicator": True, "privileged_context": privileged, "baseline_deviation": 1.0, "raw_content_persisted": False},
        confidence=0.95 if record.risk_markers else 0.8,
    )


def _connection_event(current: CollectorSnapshot, connection: ConnectionRecord, observed_at: datetime) -> SecurityEvent:
    process = connection.process_name or "unknown"
    subject = f"connection:{process}:{connection.remote_address_hash}:{connection.remote_port}"
    return SecurityEvent(
        event_id=_event_id(current.host_id, "outbound", connection.identity, observed_at.isoformat()),
        observed_at=observed_at,
        host_id=current.host_id,
        source="debian_outbound_connection_snapshot",
        kind=EventKind.OUTBOUND_CONNECTION,
        subject=subject,
        attributes={
            "protocol": connection.protocol,
            "destination_hash": connection.remote_address_hash,
            "destination_port": connection.remote_port,
            "destination_scope": connection.destination_scope,
            "process_name": connection.process_name,
            "external_destination": connection.destination_scope == "public",
            "baseline_deviation": 1.0,
            "raw_remote_address_persisted": False,
            "raw_local_address_persisted": False,
        },
        confidence=0.8 if connection.destination_scope == "public" else 0.7,
    )


def diff_snapshots(current: CollectorSnapshot, previous: CollectorSnapshot | None) -> list[SecurityEvent]:
    if previous is None:
        return []
    if current.host_id != previous.host_id:
        raise ValueError("snapshot host_id mismatch")
    observed_at = current.observed_at
    events: list[SecurityEvent] = []

    for process in _new_items(current.processes, previous.processes, key=lambda item: item.identity):
        if not process.suspicious_markers:
            continue
        subject = process.executable or process.command_name
        events.append(SecurityEvent(_event_id(current.host_id, "process", process.identity, observed_at.isoformat()), observed_at, current.host_id, "debian_process_snapshot", EventKind.PROCESS_START, subject, {"pid": process.pid, "ppid": process.ppid, "user_identity_hash": process.user, "command_name": process.command_name, "args_hash": process.args_hash, "suspicious_markers": list(process.suspicious_markers), "privileged_context": process.privileged_context or process.user == "root", "baseline_deviation": 1.0, "raw_arguments_persisted": False, "raw_username_persisted": False}, 0.9))

    for socket in _new_items(current.sockets, previous.sockets, key=lambda item: item.identity):
        subject = f"{socket.protocol}://{socket.local_address}:{socket.port}"
        events.append(SecurityEvent(_event_id(current.host_id, "socket", socket.identity, observed_at.isoformat()), observed_at, current.host_id, "debian_socket_snapshot", EventKind.NEW_LISTENING_PORT, subject, {"protocol": socket.protocol, "local_address": socket.local_address, "port": socket.port, "process_name": socket.process_name, "external_bind": socket.external_bind, "privileged_context": socket.port < 1024, "baseline_deviation": 1.0}))

    for connection in _new_items(current.connections, previous.connections, key=lambda item: item.identity):
        events.append(_connection_event(current, connection, observed_at))

    previous_containers = {item.identity: item for item in previous.containers}
    for container in current.containers:
        prior = previous_containers.get(container.identity)
        if prior is None:
            events.append(SecurityEvent(_event_id(current.host_id, "container", container.identity, observed_at.isoformat()), observed_at, current.host_id, "docker_read_only_snapshot", EventKind.CONTAINER_CHANGE, f"container:{container.name}", {"container_id_hash": container.container_id_hash, "image": container.image, "name": container.name, "status": container.status, "image_uses_latest_tag": container.image.endswith(":latest"), "security_markers": list(container.security_markers), "privileged_context": container.privileged, "persistence_indicator": bool(container.security_markers), "baseline_deviation": 1.0}, 0.9 if container.security_markers else 0.8))
            continue
        fingerprint_changed = prior.security_fingerprint is not None and container.security_fingerprint != prior.security_fingerprint
        upgrade_risk = prior.security_fingerprint is None and bool(container.security_markers)
        runtime_changed = prior.security_fingerprint is not None and (container.restart_count > prior.restart_count or container.health_status != prior.health_status)
        if fingerprint_changed or upgrade_risk or runtime_changed:
            events.append(SecurityEvent(_event_id(current.host_id, "container-config", container.identity, container.security_fingerprint, observed_at.isoformat()), observed_at, current.host_id, "docker_inspect_read_only", EventKind.CONTAINER_CONFIGURATION_CHANGE, f"container:{container.name}", {"container_id_hash": container.container_id_hash, "image": container.image, "security_markers": list(container.security_markers), "previous_security_fingerprint": prior.security_fingerprint, "current_security_fingerprint": container.security_fingerprint, "restart_count": container.restart_count, "previous_restart_count": prior.restart_count, "health_status": container.health_status, "privileged_context": container.privileged, "persistence_indicator": bool(container.security_markers), "baseline_deviation": 1.0}, 0.95))

    previous_files = {item.path: item for item in previous.files}
    for current_file in current.files:
        prior = previous_files.get(current_file.path)
        if prior is None:
            continue
        changes = _changed_fields(prior, current_file)
        if not changes:
            continue
        events.append(SecurityEvent(_event_id(current.host_id, "file", current_file.path, changes, observed_at.isoformat()), observed_at, current.host_id, "debian_file_integrity_snapshot", EventKind.SENSITIVE_FILE_CHANGE, current_file.path, {"changed_fields": list(changes), "previous_sha256": prior.sha256, "current_sha256": current_file.sha256, "previous_mode": prior.mode, "current_mode": current_file.mode, "exists": current_file.exists, "privileged_context": True, "baseline_deviation": 1.0}))

    previous_persistence = {item.identity: item for item in previous.persistence}
    current_identities = {item.identity for item in current.persistence}
    for record in current.persistence:
        prior = previous_persistence.get(record.identity)
        if prior is None:
            events.append(_persistence_event(current, record, observed_at, change_type="created"))
        elif prior.fingerprint != record.fingerprint or prior.risk_markers != record.risk_markers:
            events.append(_persistence_event(current, record, observed_at, change_type="modified", previous_fingerprint=prior.fingerprint))
    for prior in previous.persistence:
        if prior.identity in current_identities:
            continue
        tombstone = PersistenceRecord(prior.category, prior.subject, "missing", prior.risk_markers, {**prior.metadata, "exists": False})
        events.append(_persistence_event(current, tombstone, observed_at, change_type="removed", previous_fingerprint=prior.fingerprint))

    return sorted(events, key=lambda item: (item.observed_at, item.event_id))
