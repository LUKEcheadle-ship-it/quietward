from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from ..contracts import EventKind, SecurityEvent
from .command import CONNECTIONS_COMMAND, DOCKER_INSPECT_PREFIX, DOCKER_PS_COMMAND, JOURNAL_AUTH_COMMAND, PS_COMMAND, SS_COMMAND, CommandResult, CommandRunner, ReadOnlyCommandRunner
from .diff import diff_snapshots
from .files import DEFAULT_SENSITIVE_FILES, observe_file
from .models import CollectionBatch, CollectorSnapshot, ProcessRecord
from .parsers import parse_auth_journal, parse_connections_output, parse_docker_inspect_output, parse_docker_ps_ids, parse_docker_ps_output, parse_ps_output, parse_ss_output
from .persistence import observe_persistence
from .privacy import derive_host_id, redact_error
from ..privacy_identity import PrivacyIdentity

MAX_CONNECTION_RECORDS = 2_000


@dataclass(frozen=True, slots=True)
class DebianCollectorConfig:
    sensitive_files: tuple[Path, ...] = DEFAULT_SENSITIVE_FILES
    include_processes: bool = True
    include_sockets: bool = True
    include_connections: bool = False
    include_auth_journal: bool = True
    include_docker: bool = True
    include_persistence: bool = True
    max_file_hash_bytes: int = 4 * 1024 * 1024
    max_persistence_entries: int = 500
    max_docker_inspects: int = 50
    privacy_identity_key_path: Path | None = None

    def __post_init__(self) -> None:
        if self.max_file_hash_bytes <= 0 or self.max_persistence_entries <= 0 or self.max_docker_inspects <= 0:
            raise ValueError("collector limits must be positive")
        for path in self.sensitive_files:
            if not path.is_absolute():
                raise ValueError(f"sensitive file must be absolute: {path}")


class DebianReadOnlyCollector:
    def __init__(self, config: DebianCollectorConfig | None = None, runner: CommandRunner | None = None, host_id: str | None = None) -> None:
        self.config = config or DebianCollectorConfig()
        self.runner = runner or ReadOnlyCommandRunner()
        self.host_id = host_id or derive_host_id()
        self.privacy_identity: PrivacyIdentity | None = None
        if (self.config.include_auth_journal or self.config.include_processes) and self.config.privacy_identity_key_path is not None:
            try:
                self.privacy_identity = PrivacyIdentity.load(self.config.privacy_identity_key_path)
            except ValueError:
                self.privacy_identity = None

    def collect(self, previous: CollectorSnapshot | None = None) -> CollectionBatch:
        observed_at = datetime.now(timezone.utc)
        errors: list[str] = []
        processes = ()
        sockets = ()
        connections = ()
        containers = ()

        if self.config.include_processes:
            result = self.runner.run(PS_COMMAND)
            if self._ok(result, "process inventory", errors):
                parsed_processes = parse_ps_output(result.stdout)
                processes = tuple(
                    ProcessRecord(
                        item.pid,
                        item.ppid,
                        self.privacy_identity.identify(item.user) if self.privacy_identity else "unavailable",
                        item.command_name,
                        item.executable,
                        item.args_hash,
                        item.suspicious_markers,
                        item.user == "root",
                    )
                    for item in parsed_processes
                )

        if self.config.include_sockets:
            result = self.runner.run(SS_COMMAND)
            if self._ok(result, "listening socket inventory", errors):
                sockets = parse_ss_output(result.stdout)

        if self.config.include_connections:
            result = self.runner.run(CONNECTIONS_COMMAND)
            if self._ok(result, "outbound connection inventory", errors):
                connections = parse_connections_output(result.stdout)[:MAX_CONNECTION_RECORDS]

        if self.config.include_docker:
            result = self.runner.run(DOCKER_PS_COMMAND)
            if self._ok(result, "Docker inventory", errors, optional=True):
                base = parse_docker_ps_output(result.stdout)
                ids = parse_docker_ps_ids(result.stdout)
                enriched = []
                for index, record in enumerate(base):
                    if index >= self.config.max_docker_inspects or index >= len(ids):
                        enriched.append(record)
                        continue
                    inspect = self.runner.run((*DOCKER_INSPECT_PREFIX, ids[index]))
                    if self._ok(inspect, f"Docker inspect {record.name}", errors, optional=True):
                        enriched.append(parse_docker_inspect_output(inspect.stdout, record))
                    else:
                        enriched.append(record)
                containers = tuple(enriched)

        files = tuple(observe_file(path, self.config.max_file_hash_bytes) for path in self.config.sensitive_files)
        for record in files:
            if record.error:
                errors.append(f"file observation {record.path}: {record.error}")

        persistence = ()
        if self.config.include_persistence:
            persistence, persistence_errors = observe_persistence(max_entries=self.config.max_persistence_entries)
            errors.extend(persistence_errors)

        snapshot = CollectorSnapshot(
            observed_at=observed_at,
            host_id=self.host_id,
            processes=processes,
            sockets=sockets,
            containers=containers,
            files=files,
            errors=tuple(errors),
            persistence=persistence,
            connections=connections,
        )
        events = diff_snapshots(snapshot, previous)

        if self.config.include_auth_journal:
            result = self.runner.run(JOURNAL_AUTH_COMMAND)
            if self._ok(result, "SSH authentication journal", errors, optional=True):
                if self.privacy_identity is not None:
                    events.extend(self._auth_events(parse_auth_journal(result.stdout), observed_at))
                else:
                    errors.append("SSH authentication journal privacy identity unavailable")

        snapshot = CollectorSnapshot(
            observed_at=snapshot.observed_at,
            host_id=snapshot.host_id,
            processes=snapshot.processes,
            sockets=snapshot.sockets,
            containers=snapshot.containers,
            files=snapshot.files,
            errors=tuple(errors),
            collector_version=snapshot.collector_version,
            persistence=snapshot.persistence,
            connections=snapshot.connections,
        )
        return CollectionBatch(snapshot, tuple(events))

    @staticmethod
    def _ok(result: CommandResult, label: str, errors: list[str], optional: bool = False) -> bool:
        if result.returncode == 0:
            return True
        prefix = "optional " if optional or result.returncode == 127 else ""
        errors.append(f"{prefix}{label} unavailable: {redact_error(result.stderr)}")
        return False

    def _auth_events(self, rows: Sequence[dict[str, object]], fallback_time: datetime) -> list[SecurityEvent]:
        grouped: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
        for row in rows:
            grouped[(str(row["source_address_hash"]), str(row["user"]))].append(row)
        events: list[SecurityEvent] = []
        for (address_hash, user), group in sorted(grouped.items()):
            latest = max((item.get("observed_at") for item in group if isinstance(item.get("observed_at"), datetime)), default=fallback_time)
            if self.privacy_identity is None:
                continue
            user_identity_hash = self.privacy_identity.identify(user)
            digest = hashlib.sha256(f"{self.host_id}|auth|{address_hash}|{user_identity_hash}|{latest.isoformat()}|{len(group)}".encode()).hexdigest()[:20]
            events.append(SecurityEvent("fse-" + digest, latest, self.host_id, "journald_ssh_read_only", EventKind.AUTH_FAILURE, f"auth:{address_hash}:user-{user_identity_hash}", {"source_address_hash": address_hash, "user_identity_hash": user_identity_hash, "failed_count": len(group), "raw_source_address_persisted": False, "raw_username_persisted": False, "raw_log_message_persisted": False}))
        return events
