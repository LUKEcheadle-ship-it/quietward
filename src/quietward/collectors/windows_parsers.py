from __future__ import annotations

import hashlib
import ipaddress
import json
import ntpath
from datetime import datetime, timezone
from typing import Any

from ..contracts import EventKind, SecurityEvent
from ..privacy_identity import PrivacyIdentity
from .models import ConnectionRecord, DefenderStatus, PersistenceRecord, ProcessRecord, SocketRecord
from .privacy import stable_hash

_DOCUMENT_PARENTS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "onenote.exe",
    "acrord32.exe",
    "acrobat.exe",
}
_DOCUMENT_CHILD_EXECUTORS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
}


def parse_windows_defender(text: str) -> DefenderStatus | None:
    rows = _records(text)
    if not rows:
        return None
    row = rows[0]

    def optional_bool(name: str) -> bool | None:
        return bool(row[name]) if row.get(name) is not None else None

    return DefenderStatus(
        antivirus_enabled=optional_bool("AntivirusEnabled"),
        real_time_protection_enabled=optional_bool("RealTimeProtectionEnabled"),
        signature_version=_string(row.get("AntivirusSignatureVersion")) or None,
        signature_age_days=_integer(row.get("AntivirusSignatureAge"), -1)
        if row.get("AntivirusSignatureAge") is not None
        else None,
        last_quick_scan=_string(row.get("QuickScanEndTime")) or None,
        active_threat_count=_integer(row.get("ActiveThreatCount"), 0),
        remediation_required=optional_bool("RemediationRequired"),
    )


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
        raise ValueError("Windows collector output must be a JSON object or array")
    return [dict(item) for item in value if isinstance(item, dict)]


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _string(value: Any) -> str:
    return str(value or "").strip()


def _command_markers(executable: str, command_line: str) -> tuple[str, ...]:
    combined = f"{executable} {command_line}".lower()
    markers: list[str] = []
    if any(
        token in combined
        for token in (" -enc ", " -encodedcommand ", "frombase64string")
    ):
        markers.append("encoded_command")
    if any(
        token in combined
        for token in (
            "downloadstring(",
            "invoke-webrequest",
            "curl.exe http",
            "certutil -urlcache",
        )
    ):
        markers.append("network_payload_retrieval")
    if any(
        token in executable.lower()
        for token in ("\\temp\\", "\\appdata\\", "\\downloads\\")
    ):
        markers.append("user_writable_executable")
    if any(
        token in combined
        for token in (
            "rundll32 javascript:",
            "regsvr32 /s /n /u /i:http",
        )
    ):
        markers.append("living_off_the_land_pattern")
    if any(
        token in combined
        for token in (
            "system.net.sockets.tcpclient",
            "net.sockets.tcpclient",
            "new-object net.sockets.tcpclient",
        )
    ):
        markers.append("reverse_shell")
    if any(
        token in combined
        for token in (
            "mimikatz",
            "sekurlsa::logonpasswords",
            "sekurlsa::wdigest",
            "lsadump::sam",
            "lsadump::secrets",
        )
    ) or (
        "comsvcs.dll" in combined
        and "minidump" in combined
        and "lsass" in combined
    ):
        markers.append("credential_dumping")
    return tuple(sorted(set(markers)))


def parse_windows_processes(
    text: str,
    privacy_identity: PrivacyIdentity | None,
) -> tuple[ProcessRecord, ...]:
    base: list[ProcessRecord] = []
    for row in _records(text):
        pid = _integer(row.get("ProcessId"))
        if pid <= 0:
            continue
        ppid = max(0, _integer(row.get("ParentProcessId")))
        command_name = _string(row.get("Name")) or "unknown"
        raw_executable = _string(row.get("ExecutablePath"))
        executable = ntpath.basename(raw_executable) or command_name
        command_line = _string(row.get("CommandLine"))
        raw_user = _string(row.get("UserName"))
        user_identity = (
            privacy_identity.identify_scoped(
                raw_user.casefold(),
                "windows-process-account-v1",
            )
            if privacy_identity is not None and raw_user
            else "unavailable"
        )
        normalized_user = raw_user.casefold()
        privileged = normalized_user.endswith("\\system") or normalized_user in {
            "system",
            "nt authority\\system",
            "local system",
        }
        base.append(
            ProcessRecord(
                pid=pid,
                ppid=ppid,
                user=user_identity,
                command_name=command_name,
                executable=executable,
                args_hash=(
                    privacy_identity.identify_scoped(
                        command_line,
                        "windows-process-command-v1",
                    )
                    if privacy_identity is not None and command_line
                    else "unavailable"
                ),
                suspicious_markers=_command_markers(raw_executable, command_line),
                privileged_context=privileged,
            )
        )

    by_pid = {item.pid: item for item in base}
    result: list[ProcessRecord] = []
    for item in base:
        markers = set(item.suspicious_markers)
        parent = by_pid.get(item.ppid)
        parent_name = (
            (parent.executable or parent.command_name).casefold()
            if parent is not None
            else ""
        )
        child_name = (item.executable or item.command_name).casefold()
        if parent_name in _DOCUMENT_PARENTS and child_name in _DOCUMENT_CHILD_EXECUTORS:
            markers.add("document_spawned_interpreter")
        result.append(
            ProcessRecord(
                pid=item.pid,
                ppid=item.ppid,
                user=item.user,
                command_name=item.command_name,
                executable=item.executable,
                args_hash=item.args_hash,
                suspicious_markers=tuple(sorted(markers)),
                privileged_context=item.privileged_context,
            )
        )
    return tuple(sorted(result, key=lambda item: item.pid))


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


def _destination_scope(address: str) -> str:
    try:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return "unknown"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_unspecified:
        return "unspecified"
    if parsed.is_link_local:
        return "link_local"
    if parsed.is_multicast:
        return "multicast"
    if parsed.is_private:
        return "private"
    if parsed.is_global:
        return "public"
    return "reserved"


def parse_windows_sockets(text: str) -> tuple[SocketRecord, ...]:
    result: list[SocketRecord] = []
    seen: set[tuple[str, str, int, str | None]] = set()
    for row in _records(text):
        port = _integer(row.get("LocalPort"), -1)
        if not 0 <= port <= 65535:
            continue
        process = _string(row.get("ProcessName")) or None
        item = SocketRecord(
            protocol=(_string(row.get("Protocol")) or "tcp").lower(),
            local_address=_local_scope(_string(row.get("LocalAddress"))),
            port=port,
            process_name=process,
        )
        identity = item.identity
        if identity not in seen:
            seen.add(identity)
            result.append(item)
    return tuple(sorted(result, key=lambda item: item.identity))


def parse_windows_connections(
    text: str,
    *,
    namespace: str = "quietward-v1",
) -> tuple[ConnectionRecord, ...]:
    result: list[ConnectionRecord] = []
    seen: set[tuple[str, str, int, str | None]] = set()
    for row in _records(text):
        address = _string(row.get("RemoteAddress"))
        port = _integer(row.get("RemotePort"), -1)
        if not address or not 0 <= port <= 65535:
            continue
        scope = _destination_scope(address)
        process = _string(row.get("ProcessName")) or None
        item = ConnectionRecord(
            protocol=(_string(row.get("Protocol")) or "tcp").lower(),
            remote_address_hash=stable_hash(
                f"outbound:{address}",
                20,
                namespace=namespace,
            ),
            remote_port=port,
            destination_scope=scope,
            process_name=process,
        )
        if item.identity not in seen:
            seen.add(item.identity)
            result.append(item)
    return tuple(sorted(result, key=lambda item: item.identity))


def parse_windows_auth_events(
    text: str,
    *,
    host_id: str,
    privacy_identity: PrivacyIdentity | None,
    fallback_time: datetime,
) -> tuple[SecurityEvent, ...]:
    rows = _records(text)
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    source_users: dict[str, set[str]] = {}
    source_failures: dict[str, int] = {}
    for row in rows:
        raw_user = _string(row.get("User")) or "unknown"
        raw_address = _string(row.get("SourceAddress")) or "unknown"
        address_hash = stable_hash(
            raw_address,
            16,
            namespace="quietward-windows-auth-v1",
        )
        user_identity = (
            privacy_identity.identify_scoped(
                raw_user.casefold(),
                "windows-auth-account-v1",
            )
            if privacy_identity is not None
            else "unavailable"
        )
        grouped.setdefault((address_hash, user_identity), []).append(row)
        source_users.setdefault(address_hash, set()).add(user_identity)
        source_failures[address_hash] = source_failures.get(address_hash, 0) + 1

    events: list[SecurityEvent] = []
    for (address_hash, user_identity), group in sorted(grouped.items()):
        latest = fallback_time
        for row in group:
            raw_time = row.get("TimeCreated")
            if raw_time:
                try:
                    parsed = datetime.fromisoformat(str(raw_time).replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    latest = max(latest, parsed.astimezone(timezone.utc))
                except ValueError:
                    pass
        total_from_source = source_failures[address_hash]
        distinct_accounts = len(source_users[address_hash])
        spray_candidate = total_from_source >= 10 and distinct_accounts >= 5
        event_id = "fse-" + hashlib.sha256(
            f"{host_id}|windows-auth|{address_hash}|{user_identity}|{latest.isoformat()}|{len(group)}".encode()
        ).hexdigest()[:20]
        events.append(
            SecurityEvent(
                event_id=event_id,
                observed_at=latest,
                host_id=host_id,
                source="windows_security_log_read_only",
                kind=EventKind.AUTH_FAILURE,
                subject=f"auth:{address_hash}:user-{user_identity}",
                attributes={
                    "source_address_hash": address_hash,
                    "user_identity_hash": user_identity,
                    "failed_count": len(group),
                    "source_failed_count": total_from_source,
                    "distinct_accounts": distinct_accounts,
                    "credential_spray_candidate": spray_candidate,
                    "suspicious_markers": ["credential_spray"] if spray_candidate else [],
                    "raw_source_address_persisted": False,
                    "raw_username_persisted": False,
                    "raw_log_message_persisted": False,
                },
                confidence=0.98 if spray_candidate else 0.95 if len(group) >= 5 else 0.8,
            )
        )
    return tuple(events)


def parse_windows_persistence(
    text: str,
    privacy_identity: PrivacyIdentity | None,
) -> tuple[PersistenceRecord, ...]:
    records: list[PersistenceRecord] = []
    for row in _records(text):
        category = (_string(row.get("Category")) or "unknown").lower()
        subject = _string(row.get("Subject")) or "unknown"
        fingerprint = _string(row.get("Fingerprint"))
        raw_user = _string(row.get("User"))
        metadata: dict[str, object] = {
            "source": _string(row.get("Source")) or "windows-read-only",
        }
        if raw_user:
            metadata["user_identity_hash"] = (
                privacy_identity.identify_scoped(
                    raw_user.casefold(),
                    "windows-persistence-account-v1",
                )
                if privacy_identity is not None
                else "unavailable"
            )
        risk_markers = tuple(
            sorted(
                {
                    str(item).strip()
                    for item in row.get("RiskMarkers", [])
                    if str(item).strip()
                }
            )
        )
        records.append(
            PersistenceRecord(
                category=category,
                subject=subject,
                fingerprint=fingerprint,
                risk_markers=risk_markers,
                metadata=metadata,
            )
        )
    return tuple(records)
