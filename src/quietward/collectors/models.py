from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..contracts import SecurityEvent


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class ProcessRecord:
    pid: int
    ppid: int
    user: str
    command_name: str
    executable: str
    args_hash: str
    suspicious_markers: tuple[str, ...] = ()
    privileged_context: bool = False

    @property
    def identity(self):
        return self.user, self.command_name, self.executable, self.args_hash

    def to_dict(self):
        identity = self.user if len(self.user) == 32 and all(char in "0123456789abcdef" for char in self.user) else "unavailable"
        return {"pid": self.pid, "ppid": self.ppid, "user_identity_hash": identity, "command_name": self.command_name, "executable": self.executable, "args_hash": self.args_hash, "suspicious_markers": list(self.suspicious_markers), "privileged_context": self.privileged_context}

    @classmethod
    def from_dict(cls, value):
        return cls(int(value["pid"]), int(value["ppid"]), str(value.get("user_identity_hash") or "unavailable"), str(value["command_name"]), str(value["executable"]), str(value["args_hash"]), tuple(str(item) for item in value.get("suspicious_markers", [])), bool(value.get("privileged_context", False)))


@dataclass(frozen=True, slots=True)
class SocketRecord:
    protocol: str
    local_address: str
    port: int
    process_name: str | None = None

    @property
    def identity(self):
        return self.protocol, self.local_address, self.port, self.process_name

    @property
    def external_bind(self):
        return self.local_address in {"0.0.0.0", "::", "*"}

    def to_dict(self):
        return {"protocol": self.protocol, "local_address": self.local_address, "port": self.port, "process_name": self.process_name}

    @classmethod
    def from_dict(cls, value):
        return cls(str(value["protocol"]), str(value["local_address"]), int(value["port"]), str(value["process_name"]) if value.get("process_name") is not None else None)


@dataclass(frozen=True, slots=True)
class ConnectionRecord:
    protocol: str
    remote_address_hash: str
    remote_port: int
    destination_scope: str
    process_name: str | None = None

    @property
    def identity(self) -> tuple[str, str, int, str | None]:
        return self.protocol, self.remote_address_hash, self.remote_port, self.process_name

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "remote_address_hash": self.remote_address_hash,
            "remote_port": self.remote_port,
            "destination_scope": self.destination_scope,
            "process_name": self.process_name,
            "raw_remote_address_persisted": False,
            "raw_local_address_persisted": False,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ConnectionRecord":
        process_name = value.get("process_name")
        return cls(
            protocol=str(value["protocol"]),
            remote_address_hash=str(value["remote_address_hash"]),
            remote_port=int(value["remote_port"]),
            destination_scope=str(value.get("destination_scope") or "unknown"),
            process_name=str(process_name) if process_name is not None else None,
        )


@dataclass(frozen=True, slots=True)
class ContainerRecord:
    container_id_hash: str
    image: str
    name: str
    status: str
    privileged: bool = False
    network_mode: str | None = None
    pid_mode: str | None = None
    ipc_mode: str | None = None
    readonly_rootfs: bool | None = None
    no_new_privileges: bool | None = None
    added_capabilities: tuple[str, ...] = ()
    sensitive_mounts: tuple[str, ...] = ()
    restart_count: int = 0
    health_status: str | None = None
    security_markers: tuple[str, ...] = ()
    security_fingerprint: str | None = None

    @property
    def identity(self):
        return self.container_id_hash, self.image, self.name

    def to_dict(self):
        return {"container_id_hash": self.container_id_hash, "image": self.image, "name": self.name, "status": self.status, "privileged": self.privileged, "network_mode": self.network_mode, "pid_mode": self.pid_mode, "ipc_mode": self.ipc_mode, "readonly_rootfs": self.readonly_rootfs, "no_new_privileges": self.no_new_privileges, "added_capabilities": list(self.added_capabilities), "sensitive_mounts": list(self.sensitive_mounts), "restart_count": self.restart_count, "health_status": self.health_status, "security_markers": list(self.security_markers), "security_fingerprint": self.security_fingerprint}

    @classmethod
    def from_dict(cls, value):
        return cls(str(value["container_id_hash"]), str(value["image"]), str(value["name"]), str(value["status"]), bool(value.get("privileged", False)), str(value["network_mode"]) if value.get("network_mode") is not None else None, str(value["pid_mode"]) if value.get("pid_mode") is not None else None, str(value["ipc_mode"]) if value.get("ipc_mode") is not None else None, bool(value["readonly_rootfs"]) if value.get("readonly_rootfs") is not None else None, bool(value["no_new_privileges"]) if value.get("no_new_privileges") is not None else None, tuple(str(item) for item in value.get("added_capabilities", [])), tuple(str(item) for item in value.get("sensitive_mounts", [])), int(value.get("restart_count", 0)), str(value["health_status"]) if value.get("health_status") is not None else None, tuple(str(item) for item in value.get("security_markers", [])), str(value["security_fingerprint"]) if value.get("security_fingerprint") is not None else None)


@dataclass(frozen=True, slots=True)
class FileRecord:
    path: str
    exists: bool
    file_type: str
    mode: int | None
    size: int | None
    mtime_ns: int | None
    sha256: str | None
    error: str | None = None

    @property
    def identity(self):
        return self.path

    def to_dict(self):
        return {"path": self.path, "exists": self.exists, "file_type": self.file_type, "mode": self.mode, "size": self.size, "mtime_ns": self.mtime_ns, "sha256": self.sha256, "error": self.error}

    @classmethod
    def from_dict(cls, value):
        return cls(str(value["path"]), bool(value["exists"]), str(value["file_type"]), int(value["mode"]) if value.get("mode") is not None else None, int(value["size"]) if value.get("size") is not None else None, int(value["mtime_ns"]) if value.get("mtime_ns") is not None else None, str(value["sha256"]) if value.get("sha256") is not None else None, str(value["error"]) if value.get("error") is not None else None)


@dataclass(frozen=True, slots=True)
class PersistenceRecord:
    category: str
    subject: str
    fingerprint: str
    risk_markers: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def identity(self):
        return self.category, self.subject

    def to_dict(self):
        return {"category": self.category, "subject": self.subject, "fingerprint": self.fingerprint, "risk_markers": list(self.risk_markers), "metadata": self.metadata}

    @classmethod
    def from_dict(cls, value):
        return cls(str(value["category"]), str(value["subject"]), str(value["fingerprint"]), tuple(str(item) for item in value.get("risk_markers", [])), dict(value.get("metadata") or {}))


@dataclass(frozen=True, slots=True)
class DefenderStatus:
    antivirus_enabled: bool | None = None
    real_time_protection_enabled: bool | None = None
    signature_version: str | None = None
    signature_age_days: int | None = None
    last_quick_scan: str | None = None
    active_threat_count: int | None = None
    remediation_required: bool | None = None

    def to_dict(self):
        return {"source": "microsoft_defender", "antivirus_enabled": self.antivirus_enabled, "real_time_protection_enabled": self.real_time_protection_enabled, "signature_version": self.signature_version, "signature_age_days": self.signature_age_days, "last_quick_scan": self.last_quick_scan, "active_threat_count": self.active_threat_count, "remediation_required": self.remediation_required, "quietward_malware_verdict": False}

    @classmethod
    def from_dict(cls, value):
        return cls(value.get("antivirus_enabled"), value.get("real_time_protection_enabled"), value.get("signature_version"), value.get("signature_age_days"), value.get("last_quick_scan"), value.get("active_threat_count"), value.get("remediation_required"))


@dataclass(frozen=True, slots=True)
class CollectorSnapshot:
    observed_at: datetime
    host_id: str
    processes: tuple[ProcessRecord, ...] = ()
    sockets: tuple[SocketRecord, ...] = ()
    containers: tuple[ContainerRecord, ...] = ()
    files: tuple[FileRecord, ...] = ()
    errors: tuple[str, ...] = ()
    collector_version: str = "debian-read-only-v3"
    persistence: tuple[PersistenceRecord, ...] = ()
    connections: tuple[ConnectionRecord, ...] = ()
    defender: DefenderStatus | None = None

    def to_dict(self):
        return {
            "collector_version": self.collector_version,
            "observed_at": _utc(self.observed_at),
            "host_id": self.host_id,
            "processes": [item.to_dict() for item in self.processes],
            "sockets": [item.to_dict() for item in self.sockets],
            "containers": [item.to_dict() for item in self.containers],
            "files": [item.to_dict() for item in self.files],
            "persistence": [item.to_dict() for item in self.persistence],
            "connections": [item.to_dict() for item in self.connections],
            "errors": list(self.errors),
            "defender": self.defender.to_dict() if self.defender is not None else None,
        }

    @classmethod
    def from_dict(cls, value):
        return cls(
            datetime.fromisoformat(str(value["observed_at"]).replace("Z", "+00:00")),
            str(value["host_id"]),
            tuple(ProcessRecord.from_dict(item) for item in value.get("processes", [])),
            tuple(SocketRecord.from_dict(item) for item in value.get("sockets", [])),
            tuple(ContainerRecord.from_dict(item) for item in value.get("containers", [])),
            tuple(FileRecord.from_dict(item) for item in value.get("files", [])),
            tuple(str(item) for item in value.get("errors", [])),
            str(value.get("collector_version") or "debian-read-only-v1"),
            tuple(PersistenceRecord.from_dict(item) for item in value.get("persistence", [])),
            tuple(ConnectionRecord.from_dict(item) for item in value.get("connections", [])),
            DefenderStatus.from_dict(value["defender"]) if value.get("defender") else None,
        )


@dataclass(frozen=True, slots=True)
class CollectionBatch:
    snapshot: CollectorSnapshot
    events: tuple[SecurityEvent, ...] = field(default_factory=tuple)

    def to_dict(self):
        return {"snapshot": self.snapshot.to_dict(), "events": [item.to_dict() for item in self.events]}
