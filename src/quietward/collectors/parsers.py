from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath

from .models import ConnectionRecord, ContainerRecord, ProcessRecord, SocketRecord
from .privacy import stable_hash

_VOLATILE_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
_MINER_NAMES = {"xmrig", "minerd", "cpuminer", "ethminer"}
_RELAY_NAMES = {"nc", "ncat", "netcat", "socat"}
_LINUX_SHELL_NAMES = {"bash", "sh", "dash", "zsh", "ksh"}
_LINUX_WEB_PARENT_NAMES = {
    "apache2",
    "httpd",
    "nginx",
    "lighttpd",
    "gunicorn",
    "uwsgi",
}
_PARENT_CHILD_SUSPICIOUS_MARKERS = {
    "reverse_shell",
    "download_execute_chain",
    "encoded_shell_chain",
}
_AUTH_PATTERNS = (
    re.compile(r"failed password", re.I),
    re.compile(r"authentication failure", re.I),
    re.compile(r"invalid user", re.I),
    re.compile(r"maximum authentication attempts", re.I),
)
_IP_PATTERN = re.compile(r"\b(?:from|rhost=)(?P<ip>[0-9a-fA-F:.]+)")
_USER_PATTERNS = (
    re.compile(r"invalid user\s+(?P<user>[A-Za-z0-9_.@-]+)", re.I),
    re.compile(r"for\s+(?P<user>[A-Za-z0-9_.@-]+)", re.I),
    re.compile(r"user=(?P<user>[A-Za-z0-9_.@-]+)", re.I),
)
_SENSITIVE_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "DAC_OVERRIDE"}


def _args_hash(args: str) -> str:
    return hashlib.sha256(args.encode("utf-8", errors="replace")).hexdigest()[:24]


def _markers(command_name: str, executable: str, args: str) -> tuple[str, ...]:
    lowered = args.lower()
    name = command_name.lower()
    markers: set[str] = set()
    if any(executable.startswith(prefix) for prefix in _VOLATILE_PREFIXES):
        markers.add("volatile_directory_executable")
    if name in _MINER_NAMES or any(token in lowered for token in ("xmrig", "stratum+tcp", "minerd")):
        markers.add("cryptominer_indicator")
    if name in _RELAY_NAMES and re.search(r"(?:^|\s)-[^\s]*l", lowered):
        markers.add("network_listener_tool")
    if name in _RELAY_NAMES and (
        re.search(r"(?:^|\s)-[^\s]*e(?:\s|$)", lowered)
        or "exec:" in lowered
    ):
        markers.add("reverse_shell")
    if name in _LINUX_SHELL_NAMES and "/dev/tcp/" in lowered:
        markers.add("reverse_shell")
    if ("curl " in lowered or "wget " in lowered) and re.search(r"\|\s*(?:ba)?sh\b", lowered):
        markers.add("download_execute_chain")
    if "base64 -d" in lowered and re.search(r"\|\s*(?:ba)?sh\b", lowered):
        markers.add("encoded_shell_chain")
    return tuple(sorted(markers))


def _linux_parent_child_markers(records: list[ProcessRecord]) -> tuple[ProcessRecord, ...]:
    by_pid = {record.pid: record for record in records}
    enriched: list[ProcessRecord] = []
    for record in records:
        markers = set(record.suspicious_markers)
        parent = by_pid.get(record.ppid)
        if parent is not None:
            parent_name = parent.command_name.lower()
            child_name = record.command_name.lower()
            web_parent = parent_name in _LINUX_WEB_PARENT_NAMES or parent_name.startswith("php-fpm")
            if (
                web_parent
                and child_name in _LINUX_SHELL_NAMES
                and markers & _PARENT_CHILD_SUSPICIOUS_MARKERS
            ):
                markers.add("web_server_spawned_suspicious_shell")
        enriched.append(
            ProcessRecord(
                record.pid,
                record.ppid,
                record.user,
                record.command_name,
                record.executable,
                record.args_hash,
                tuple(sorted(markers)),
                record.privileged_context,
            )
        )
    return tuple(enriched)


def parse_ps_output(text: str) -> tuple[ProcessRecord, ...]:
    records: list[ProcessRecord] = []
    for line in text.splitlines():
        parts = line.strip().split(None, 4)
        if len(parts) < 4:
            continue
        pid_raw, ppid_raw, user, command_name = parts[:4]
        args = parts[4] if len(parts) == 5 else command_name
        try:
            pid = int(pid_raw)
            ppid = int(ppid_raw)
        except ValueError:
            continue
        first = args.split(None, 1)[0] if args.strip() else command_name
        executable = first if first.startswith("/") else command_name
        records.append(
            ProcessRecord(
                pid,
                ppid,
                user,
                command_name,
                executable,
                _args_hash(args),
                _markers(command_name, executable, args),
            )
        )
    return _linux_parent_child_markers(records)


def _split_host_port(value: str) -> tuple[str, int] | None:
    value = value.strip()
    if value.startswith("[") and "]:" in value:
        host, port_raw = value[1:].rsplit("]:", 1)
    elif ":" in value:
        host, port_raw = value.rsplit(":", 1)
    else:
        return None
    try:
        return host or "*", int(port_raw)
    except ValueError:
        return None


def _process_name(value: str) -> str | None:
    match = re.search(r'\(\("(?P<name>[^"]+)"', value)
    return match.group("name")[:200] if match else None


def parse_ss_output(text: str) -> tuple[SocketRecord, ...]:
    records = []
    for line in text.splitlines():
        parts = line.strip().split(None, 6)
        if len(parts) < 5:
            continue
        local = _split_host_port(parts[4])
        if local is None:
            continue
        process_name = _process_name(parts[6]) if len(parts) == 7 else None
        records.append(SocketRecord(parts[0].lower(), local[0], local[1], process_name))
    return tuple(records)


def _destination_scope(host: str) -> str:
    normalized = host.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "loopback"
    if address.is_unspecified:
        return "unspecified"
    if address.is_link_local:
        return "link_local"
    if address.is_multicast:
        return "multicast"
    if address.is_private:
        return "private"
    if address.is_global:
        return "public"
    return "reserved"


def parse_connections_output(
    text: str,
    *,
    namespace: str = "quietward-v1",
) -> tuple[ConnectionRecord, ...]:
    records: list[ConnectionRecord] = []
    for line in text.splitlines():
        parts = line.strip().split(None, 6)
        if len(parts) < 6:
            continue
        remote = _split_host_port(parts[5])
        if remote is None:
            continue
        host, port = remote
        if host in {"*", "0.0.0.0", "::"}:
            continue
        process_name = _process_name(parts[6]) if len(parts) == 7 else None
        records.append(
            ConnectionRecord(
                protocol=parts[0].lower(),
                remote_address_hash=stable_hash(
                    f"outbound:{host}", 20, namespace=namespace
                ),
                remote_port=port,
                destination_scope=_destination_scope(host),
                process_name=process_name,
            )
        )
    return tuple(sorted(set(records), key=lambda item: item.identity))


def parse_docker_ps_ids(text: str) -> tuple[str, ...]:
    ids = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            raw = str(row.get("ID") or row.get("Id") or "")
            if re.fullmatch(r"[a-fA-F0-9]{12,64}", raw):
                ids.append(raw)
    return tuple(ids)


def parse_docker_ps_output(
    text: str,
    *,
    namespace: str = "quietward-v1",
) -> tuple[ContainerRecord, ...]:
    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        container_id = str(row.get("ID") or row.get("Id") or "")
        image = str(row.get("Image") or "unknown")
        name = str(row.get("Names") or row.get("Name") or "unknown")
        status = str(row.get("Status") or row.get("State") or "unknown")
        records.append(ContainerRecord(stable_hash(container_id or f"{image}|{name}", 16, namespace=namespace), image[:300], PurePosixPath(name).name[:200], status[:300]))
    return tuple(records)


def _mount_category(source: str, destination: str) -> str | None:
    source = source.rstrip("/") or "/"
    destination = destination.rstrip("/") or "/"
    if source == "/var/run/docker.sock" or destination == "/var/run/docker.sock":
        return "docker_socket"
    if source == "/":
        return "host_root"
    if source.startswith("/etc") or destination.startswith("/etc"):
        return "etc"
    if source.startswith("/proc") or destination.startswith("/proc"):
        return "proc"
    if source.startswith("/sys") or destination.startswith("/sys"):
        return "sys"
    if source.startswith("/dev") or destination.startswith("/dev"):
        return "dev"
    if source.startswith("/var/run") or destination.startswith("/var/run"):
        return "var_run"
    return None


def parse_docker_inspect_output(text: str, base: ContainerRecord) -> ContainerRecord:
    try:
        raw = json.loads(text.strip())
    except json.JSONDecodeError:
        return base
    if isinstance(raw, list):
        raw = raw[0] if raw else {}
    if not isinstance(raw, dict):
        return base
    host = raw.get("HostConfig") if isinstance(raw.get("HostConfig"), dict) else {}
    state = raw.get("State") if isinstance(raw.get("State"), dict) else {}
    config = raw.get("Config") if isinstance(raw.get("Config"), dict) else {}
    privileged = bool(host.get("Privileged", False))
    network = str(host.get("NetworkMode") or "")
    pid_mode = str(host.get("PidMode") or "")
    ipc_mode = str(host.get("IpcMode") or "")
    readonly = bool(host.get("ReadonlyRootfs", False))
    security_options = tuple(str(item) for item in host.get("SecurityOpt") or [])
    no_new_privileges = any("no-new-privileges" in item for item in security_options)
    capabilities = tuple(sorted({str(item).upper() for item in host.get("CapAdd") or []}))
    mounts: set[str] = set()
    raw_mounts = raw.get("Mounts") if isinstance(raw.get("Mounts"), list) else []
    for item in raw_mounts:
        if isinstance(item, dict):
            category = _mount_category(str(item.get("Source") or ""), str(item.get("Destination") or ""))
            if category:
                mounts.add(category)
    markers: set[str] = set()
    if privileged:
        markers.add("privileged_container")
    if network == "host":
        markers.add("host_network")
    if pid_mode == "host":
        markers.add("host_pid")
    if ipc_mode == "host":
        markers.add("host_ipc")
    if "docker_socket" in mounts:
        markers.add("docker_socket_mount")
    if "host_root" in mounts:
        markers.add("host_root_mount")
    if mounts & {"etc", "proc", "sys", "dev", "var_run"}:
        markers.add("sensitive_host_mount")
    if set(capabilities) & _SENSITIVE_CAPS:
        markers.add("sensitive_capability")
    if not no_new_privileges:
        markers.add("no_new_privileges_missing")
    restart_count = int(raw.get("RestartCount") or 0)
    health = None
    if isinstance(state.get("Health"), dict):
        health = str(state["Health"].get("Status") or "") or None
    if restart_count >= 5:
        markers.add("restart_loop")
    if health == "unhealthy":
        markers.add("unhealthy_container")
    subset = {"privileged": privileged, "network": network, "pid": pid_mode, "ipc": ipc_mode, "readonly": readonly, "no_new": no_new_privileges, "caps": capabilities, "mounts": sorted(mounts), "image": str(config.get("Image") or base.image)}
    fingerprint = hashlib.sha256(json.dumps(subset, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return ContainerRecord(base.container_id_hash, base.image, base.name, base.status, privileged, network or None, pid_mode or None, ipc_mode or None, readonly, no_new_privileges, capabilities, tuple(sorted(mounts)), restart_count, health, tuple(sorted(markers)), fingerprint)


def parse_auth_journal(
    text: str,
    *,
    namespace: str = "quietward-v1",
) -> list[dict[str, object]]:
    matches = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        message = str(row.get("MESSAGE") or "")
        if not any(pattern.search(message) for pattern in _AUTH_PATTERNS):
            continue
        timestamp = datetime.now(timezone.utc)
        raw = row.get("__REALTIME_TIMESTAMP")
        try:
            if raw is not None:
                timestamp = datetime.fromtimestamp(int(str(raw)) / 1_000_000, tz=timezone.utc)
        except (TypeError, ValueError, OSError):
            pass
        ip_match = _IP_PATTERN.search(message)
        address_hash = stable_hash(
            ip_match.group("ip"), 16, namespace=namespace
        ) if ip_match else "unknown"
        user = "unknown"
        for pattern in _USER_PATTERNS:
            found = pattern.search(message)
            if found:
                user = found.group("user")[:100]
                break
        matches.append({"observed_at": timestamp, "source_address_hash": address_hash, "user": user, "message_class": "ssh_authentication_failure"})
    return matches
