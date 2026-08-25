"""Bounded client and rules for the optional local telemetry helper.

The helper is deliberately a one-way, local metadata producer.  This module
never opens a privileged source and accepts only the versioned, normalized
records emitted by that helper.
"""
from __future__ import annotations

import hashlib
import json
import socket
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..contracts import EventKind, SecurityEvent

SCHEMA_VERSION = "1.0"
MAX_FRAME_BYTES = 1_000_000
PROCESS_BURST_MINIMUM = 8
PROCESS_BURST_PARENT_FANOUT = 6


def _event_id(*parts: object) -> str:
    return "qwt-" + hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:20]


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("observed_at must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must be timezone-aware")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class TransientRecord:
    sequence: int
    observed_at: datetime
    event_type: str
    data: dict[str, Any]

    @classmethod
    def from_dict(cls, value: object) -> "TransientRecord":
        if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("unsupported telemetry record")
        sequence = value.get("sequence")
        event_type = value.get("event_type")
        data = value.get("data")
        if not isinstance(sequence, int) or sequence < 1 or not isinstance(event_type, str) or not isinstance(data, dict):
            raise ValueError("malformed telemetry record")
        # The helper contract permits only normalized metadata; reject obvious
        # accidental raw argument fields at the boundary.
        if any(key in data for key in ("argv", "arguments", "command_line", "raw_command", "source", "destination", "path")):
            raise ValueError("raw command evidence is not permitted")
        return cls(sequence, _timestamp(value.get("observed_at")), event_type, data)


class TransientTelemetryClient:
    def __init__(self, socket_path: Path, state_path: Path, *, limit: int = 512, timeout: float = 1.0) -> None:
        self.socket_path, self.state_path, self.limit, self.timeout = socket_path, state_path, limit, timeout
        if not 1 <= limit <= 4096:
            raise ValueError("telemetry limit must be between 1 and 4096")

    def _cursor(self) -> int:
        try:
            value = json.loads(self.state_path.read_text())
            cursor = value.get("sequence", 0)
            if not isinstance(cursor, int) or cursor < 0:
                raise ValueError
            return cursor
        except FileNotFoundError:
            return 0
        except (OSError, json.JSONDecodeError, ValueError):
            raise RuntimeError("transient telemetry cursor is corrupt")

    def _save(self, sequence: int) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"schema_version": SCHEMA_VERSION, "sequence": sequence}) + "\n")
        temporary.chmod(0o600)
        temporary.replace(self.state_path)

    def drain(self) -> tuple[list[TransientRecord], str | None]:
        try:
            after = self._cursor()
            request = json.dumps({"schema_version": SCHEMA_VERSION, "op": "drain", "after": after, "limit": self.limit}).encode() + b"\n"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(self.timeout)
                client.connect(str(self.socket_path))
                client.sendall(request)
                chunks: list[bytes] = []
                while sum(map(len, chunks)) <= MAX_FRAME_BYTES:
                    block = client.recv(65536)
                    if not block:
                        break
                    chunks.append(block)
            if sum(map(len, chunks)) > MAX_FRAME_BYTES:
                return [], "transient telemetry response exceeds bound"
            records = [TransientRecord.from_dict(json.loads(line)) for line in b"".join(chunks).splitlines() if line]
            if records != sorted(records, key=lambda item: item.sequence) or any(b.sequence <= a.sequence for a, b in zip(records, records[1:])):
                return [], "transient telemetry ordering invalid"
            if records:
                self._save(records[-1].sequence)
            return records, None
        except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
            return [], f"transient telemetry unavailable: {exc}"


def transient_events(records: list[TransientRecord], host_id: str) -> list[SecurityEvent]:
    processes = [item for item in records if item.event_type == "process_start"]
    forked = [item for item in processes if item.data.get("observation_stage") == "fork"]
    events: list[SecurityEvent] = []
    by_parent: dict[int, list[TransientRecord]] = defaultdict(list)
    for item in forked:
        ppid = item.data.get("ppid")
        if isinstance(ppid, int) and ppid >= 0:
            by_parent[ppid].append(item)
    for parent, children in sorted(by_parent.items()):
        if len(children) < PROCESS_BURST_PARENT_FANOUT or len(forked) < PROCESS_BURST_MINIMUM:
            continue
        start, end = min(item.observed_at for item in children), max(item.observed_at for item in children)
        names = sorted({str(item.data.get("process_name", "unknown"))[:100] for item in children})[:10]
        events.append(SecurityEvent(_event_id(host_id, "process-burst", parent, children[0].sequence, children[-1].sequence), end, host_id, "quietward_telemetry_helper", EventKind.PROCESS_BURST, f"process-burst:parent-{parent}", {"process_count": len(forked), "parent_pid": parent, "parent_child_count": len(children), "window_seconds": max(0.001, (end-start).total_seconds()), "process_names": names, "transient_observation": True, "raw_arguments_persisted": False, "raw_username_persisted": False, "baseline_deviation": 1.0}, 0.9))
    for item in processes:
        if item.data.get("encoded_shell_chain") is not True:
            continue
        data = item.data
        events.append(SecurityEvent(_event_id(host_id, "encoded", item.sequence), item.observed_at, host_id, "quietward_telemetry_helper", EventKind.ENCODED_COMMAND, str(data.get("process_name") or "shell"), {"pid": data.get("pid"), "ppid": data.get("ppid"), "command_name": data.get("process_name"), "args_hash": data.get("args_hash"), "encoded_argument_detected": True, "encoding_style": "base64-like", "interpreter": data.get("interpreter") or data.get("process_name"), "encoded_shell_chain": True, "transient_observation": True, "raw_arguments_persisted": False, "raw_username_persisted": False, "baseline_deviation": 1.0}, 0.9))
    files = [item for item in records if item.event_type == "file_activity"]
    if len(files) >= 40:
        start, end = files[0].observed_at, files[-1].observed_at
        operations: dict[str, int] = defaultdict(int)
        for item in files: operations[str(item.data.get("operation", "unknown"))] += 1
        events.append(SecurityEvent(_event_id(host_id, "file-churn", files[0].sequence, files[-1].sequence), end, host_id, "quietward_telemetry_helper", EventKind.SUSPICIOUS_FILE_CHURN, "file-churn:monitored-scope", {"operation_count": len(files), "operation_distribution": dict(sorted(operations.items())), "window_seconds": max(.001, (end-start).total_seconds()), "scope": "monitored", "raw_paths_persisted": False, "raw_file_content_persisted": False, "transient_observation": True, "baseline_deviation": 1.0}, .85))
    flows = [item for item in records if item.event_type == "network_flow"]
    by_source: dict[str, list[TransientRecord]] = defaultdict(list)
    by_destination: dict[tuple[str, int], list[TransientRecord]] = defaultdict(list)
    for item in flows:
        source = item.data.get("source_address_hash")
        destination, port = item.data.get("destination_hash"), item.data.get("destination_port")
        if isinstance(source, str): by_source[source].append(item)
        if isinstance(destination, str) and isinstance(port, int): by_destination[(destination, port)].append(item)
    for source, group in sorted(by_source.items()):
        ports = {item.data.get("destination_port") for item in group if isinstance(item.data.get("destination_port"), int)}
        if len(ports) >= 4:
            events.append(SecurityEvent(_event_id(host_id, "scan", source, group[0].sequence, group[-1].sequence), group[-1].observed_at, host_id, "quietward_telemetry_helper", EventKind.PORT_SCAN, "port-scan:source-" + source, {"source_address_hash": source, "distinct_port_count": len(ports), "protocol": "tcp", "window_seconds": max(.001,(group[-1].observed_at-group[0].observed_at).total_seconds()), "raw_source_address_persisted": False, "packet_payload_captured": False, "transient_observation": True, "baseline_deviation": 1.0}, .9))
    for (destination, port), group in sorted(by_destination.items()):
        if len(group) < 3: continue
        intervals = [(right.observed_at-left.observed_at).total_seconds() for left,right in zip(group,group[1:])]
        mean = sum(intervals)/len(intervals)
        if mean <= 0 or max(abs(value-mean) for value in intervals) > max(.25, mean*.25): continue
        events.append(SecurityEvent(_event_id(host_id, "beacon", destination, port, group[0].sequence, group[-1].sequence), group[-1].observed_at, host_id, "quietward_telemetry_helper", EventKind.BEACON, f"beacon:{destination}:{port}", {"destination_hash": destination, "destination_port": port, "connection_count": len(group), "mean_interval_seconds": mean, "interval_jitter_seconds": max(abs(value-mean) for value in intervals), "window_seconds": (group[-1].observed_at-group[0].observed_at).total_seconds(), "raw_destination_address_persisted": False, "packet_payload_captured": False, "transient_observation": True, "baseline_deviation": 1.0}, .85))
    auth = [item for item in records if item.event_type == "auth_failure"]
    for item in auth:
        if int(item.data.get("failed_count") or 0) < 3: continue
        data=item.data
        events.append(SecurityEvent(_event_id(host_id,"auth-burst",item.sequence),item.observed_at,host_id,"quietward_telemetry_helper",EventKind.AUTH_FAILURE,f"auth:{data.get('source_address_hash','unknown')}:user-{data.get('user_identity_hash','unknown')}",{"source_address_hash":data.get("source_address_hash"),"user_identity_hash":data.get("user_identity_hash"),"service":"ssh","failed_count":data.get("failed_count"),"window_seconds":data.get("window_seconds"),"raw_source_address_persisted":False,"raw_username_persisted":False,"raw_log_message_persisted":False,"transient_observation":True,"baseline_deviation":1.0},.9))
    by_identity: dict[tuple[str, str], list[TransientRecord]] = defaultdict(list)
    for item in auth:
        source, user = item.data.get("source_address_hash"), item.data.get("user_identity_hash")
        if isinstance(source, str) and isinstance(user, str): by_identity[(source,user)].append(item)
    for (source,user), group in sorted(by_identity.items()):
        if len(group) < 3: continue
        events.append(SecurityEvent(_event_id(host_id,"auth",source,user,group[0].sequence,group[-1].sequence),group[-1].observed_at,host_id,"quietward_telemetry_helper",EventKind.AUTH_FAILURE,f"auth:{source}:user-{user}",{"source_address_hash":source,"user_identity_hash":user,"service":"ssh","failed_count":len(group),"window_seconds":max(.001,(group[-1].observed_at-group[0].observed_at).total_seconds()),"raw_source_address_persisted":False,"raw_username_persisted":False,"raw_log_message_persisted":False,"transient_observation":True,"baseline_deviation":1.0},.9))
    return sorted(events, key=lambda item: (item.observed_at, item.event_id))
