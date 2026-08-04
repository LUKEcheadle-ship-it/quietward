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
        signature_age_days=_integer(row.get("AntivirusSignatureAge"), -1) if row.get("AntivirusSignatureAge") is not None else None,
        last_quick_scan=_string(row.get("QuickScanEndTime")) or None,
        active_threat_count=_integer(row.get("ActiveThreatCount"), 0),
        remediation_required=optional_bool("RemediationRequired"),
    )
from .privacy import stable_hash


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
    if any(token in combined for token in (" -enc ", " -encodedcommand ", "frombase64string")):
        markers.append("encoded_command")
    if any(token in combined for token in ("downloadstring(", "invoke-webrequest", "curl.exe http", "certutil -urlcache")):
        markers.append("network_payload_retrieval")
    if any(token in executable.lower() for token in ("\\temp\\", "\\appdata\\", "\\downloads\\")):
        markers.append("user_writable_executable")
    if any(token in combined for token in ("rundll32 javascript:", "regsvr32 /s /n /u /i:http")):
        markers.append("living_off_the_land_pattern")
    return tuple(sorted(set(markers)))


def parse_windows_processes(
    text: str,
    privacy_identity: PrivacyIdentity | None,
) -> tuple[ProcessRecord, ...]:
    result: list[ProcessRecord] = []
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
        result.append(
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
        if item.identity not in seen:
            seen.add(item.identity)
            result.append(item)
    return tuple(sorted(result, key=lambda item: item.identity))


def parse_windows_connections(
    text: str,
    privacy_identity: PrivacyIdentity,
    limit: int = 2000,
) -> tuple[ConnectionRecord, ...]:
    if limit <= 0:
        raise ValueError("connection limit must be positive")
    result: list[ConnectionRecord] = []
    seen: set[tuple[str, str, int, str | None]] = set()
    for row in _records(text):
        remote = _string(row.get("RemoteAddress"))
        port = _integer(row.get("RemotePort"), -1)
        if not remote or not 0 <= port <= 65535:
            continue
        process = _string(row.get("ProcessName")) or None
        item = ConnectionRecord(
            protocol=(_string(row.get("Protocol")) or "tcp").lower(),
            remote_address_hash=privacy_identity.identify_scoped(
                remote.casefold(),
                "windows-remote-address-v1",
            ),
            remote_port=port,
            destination_scope=_destination_scope(remote),
            process_name=process,
        )
        if item.identity in seen:
            continue
        seen.add(item.identity)
        result.append(item)
        if len(result) >= limit:
            break
    return tuple(sorted(result, key=lambda item: item.identity))


def _persistence_markers(category: str, command: str, account: str) -> tuple[str, ...]:
    lowered = command.lower()
    markers: list[str] = []
    if any(token in lowered for token in (" -enc ", " -encodedcommand ", "frombase64string")):
        markers.append("encoded_command")
    if any(token in lowered for token in ("\\temp\\", "\\appdata\\", "\\downloads\\")):
        markers.append("user_writable_target")
    if category == "service_auto" and account.casefold() in {
        "localsystem",
        "local system",
        "nt authority\\system",
    }:
        markers.append("privileged_service")
    if any(token in lowered for token in ("http://", "https://")):
        markers.append("network_target")
    return tuple(sorted(set(markers)))


def parse_windows_persistence(
    text: str,
    privacy_identity: PrivacyIdentity,
    limit: int = 2000,
) -> tuple[PersistenceRecord, ...]:
    if limit <= 0:
        raise ValueError("persistence limit must be positive")
    result: list[PersistenceRecord] = []
    for row in _records(text):
        category = (_string(row.get("Category")) or "unknown").lower()
        name = _string(row.get("Name"))
        if not name:
            continue
        command = _string(row.get("Command"))
        state = _string(row.get("State")) or "unknown"
        account = _string(row.get("Account"))
        subject_hash = privacy_identity.identify_scoped(
            f"{category}:{name}",
            "windows-persistence-subject-v1",
        )[:24]
        canonical = json.dumps(
            {
                "category": category,
                "name": name,
                "command": command,
                "state": state,
                "account": account,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        fingerprint = privacy_identity.identify_scoped(
            canonical,
            "windows-persistence-record-v1",
        )
        metadata: dict[str, Any] = {
            "state": state,
            "command_hash": (
                privacy_identity.identify_scoped(
                    command,
                    "windows-persistence-command-v1",
                )
                if command
                else None
            ),
            "raw_name_persisted": False,
            "raw_command_persisted": False,
            "raw_account_persisted": False,
        }
        if account:
            metadata["account_identity_hash"] = privacy_identity.identify_scoped(
                account.casefold(),
                "windows-persistence-account-v1",
            )
        result.append(
            PersistenceRecord(
                category=category,
                subject=f"windows:{category}:{subject_hash}",
                fingerprint=fingerprint,
                risk_markers=_persistence_markers(category, command, account),
                metadata=metadata,
            )
        )
        if len(result) >= limit:
            break
    return tuple(sorted(result, key=lambda item: item.identity))


def parse_windows_auth_events(
    text: str,
    *,
    host_id: str,
    privacy_identity: PrivacyIdentity | None,
    fallback_time: datetime,
) -> list[SecurityEvent]:
    if privacy_identity is None:
        return []
    grouped: dict[tuple[str, str], list[datetime]] = {}
    for row in _records(text):
        user = _string(row.get("User"))
        source = _string(row.get("SourceAddress"))
        if not user:
            user = "unknown"
        if not source or source == "-":
            source = "unknown"
        user_hash = privacy_identity.identify_scoped(
            user.casefold(),
            "windows-auth-username-v1",
        )
        source_hash = privacy_identity.identify_scoped(
            source.casefold(),
            "windows-auth-source-v1",
        )
        raw_time = _string(row.get("TimeCreated"))
        try:
            observed = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
        except ValueError:
            observed = fallback_time
        grouped.setdefault((source_hash, user_hash), []).append(observed)

    events: list[SecurityEvent] = []
    for (source_hash, user_hash), timestamps in sorted(grouped.items()):
        observed = max(timestamps, default=fallback_time)
        count = len(timestamps)
        digest = hashlib.sha256(
            f"{host_id}|windows-auth|{source_hash}|{user_hash}|{observed.isoformat()}|{count}".encode()
        ).hexdigest()[:20]
        events.append(
            SecurityEvent(
                event_id="fse-" + digest,
                observed_at=observed,
                host_id=host_id,
                source="windows_security_log_read_only",
                kind=EventKind.AUTH_FAILURE,
                subject=f"auth:{source_hash}:user-{user_hash}",
                attributes={
                    "source_address_hash": source_hash,
                    "user_identity_hash": user_hash,
                    "failed_count": count,
                    "raw_source_address_persisted": False,
                    "raw_username_persisted": False,
                    "raw_log_message_persisted": False,
                },
                confidence=0.95 if count >= 5 else 0.8,
            )
        )
    return events
