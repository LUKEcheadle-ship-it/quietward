from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from .command import (
    DOCKER_INSPECT_PREFIX,
    DOCKER_PS_COMMAND,
    CommandResult,
    CommandRunner,
    ReadOnlyCommandRunner,
)
from .diff import diff_snapshots
from .files import observe_file
from .models import CollectionBatch, CollectorSnapshot
from .parsers import (
    parse_docker_inspect_output,
    parse_docker_ps_ids,
    parse_docker_ps_output,
)
from .privacy import derive_host_id
from .retag import retag_event_sources
from .windows_commands import (
    WINDOWS_AUTH_COMMAND,
    WINDOWS_COMMANDS,
    WINDOWS_CONNECTION_COMMAND,
    WINDOWS_DEFENDER_COMMAND,
    WINDOWS_PERSISTENCE_COMMAND,
    WINDOWS_PROCESS_COMMAND,
    WINDOWS_SOCKET_COMMAND,
)
from .windows_parsers import (
    parse_windows_auth_events,
    parse_windows_connections,
    parse_windows_defender,
    parse_windows_persistence,
    parse_windows_processes,
    parse_windows_sockets,
)
from ..privacy_identity import PrivacyIdentity


@dataclass(frozen=True, slots=True)
class WindowsCollectorConfig:
    sensitive_files: tuple[Path, ...] = ()
    include_processes: bool = True
    include_sockets: bool = True
    include_connections: bool = False
    include_auth_events: bool = True
    include_docker: bool = True
    include_persistence: bool = True
    max_file_hash_bytes: int = 4 * 1024 * 1024
    max_persistence_entries: int = 2000
    max_docker_inspects: int = 50
    max_connection_records: int = 2000
    privacy_identity_key_path: Path | None = None
    privacy_identity_namespace: str = "quietward-v1"
    data_identity_namespace: str = "quietward-v1"

    def __post_init__(self) -> None:
        if (
            self.max_file_hash_bytes <= 0
            or self.max_persistence_entries <= 0
            or self.max_docker_inspects <= 0
            or self.max_connection_records <= 0
        ):
            raise ValueError("collector limits must be positive")
        for path in self.sensitive_files:
            if not path.is_absolute():
                raise ValueError(f"sensitive file must be absolute: {path}")


class WindowsReadOnlyCollector:
    def __init__(
        self,
        config: WindowsCollectorConfig | None = None,
        runner: CommandRunner | None = None,
        host_id: str | None = None,
    ) -> None:
        self.config = config or WindowsCollectorConfig()
        self.runner = runner or ReadOnlyCommandRunner(
            timeout_seconds=20.0,
            additional_commands=WINDOWS_COMMANDS,
        )
        self.host_id = host_id or derive_host_id(
            namespace=self.config.data_identity_namespace
        )
        self.privacy_identity: PrivacyIdentity | None = None
        if (
            self.config.include_processes
            or self.config.include_auth_events
            or self.config.include_persistence
        ) and self.config.privacy_identity_key_path is not None:
            try:
                self.privacy_identity = PrivacyIdentity.load(
                    self.config.privacy_identity_key_path,
                    namespace=self.config.privacy_identity_namespace,
                )
            except ValueError:
                self.privacy_identity = None

    def collect(self, previous: CollectorSnapshot | None = None) -> CollectionBatch:
        observed_at = datetime.now(timezone.utc)
        errors: list[str] = []
        processes = ()
        sockets = ()
        connections = ()
        persistence = ()
        containers = ()
        defender = None

        result = self.runner.run(WINDOWS_DEFENDER_COMMAND)
        if self._ok(result, "Microsoft Defender status", errors, optional=True):
            defender = parse_windows_defender(result.stdout)

        if self.config.include_processes:
            result = self.runner.run(WINDOWS_PROCESS_COMMAND)
            if self._ok(result, "Windows process inventory", errors):
                if self.privacy_identity is None:
                    errors.append(
                        "Windows process privacy identity unavailable; account "
                        "identities omitted"
                    )
                processes = parse_windows_processes(
                    result.stdout,
                    self.privacy_identity,
                )

        if self.config.include_sockets:
            result = self.runner.run(WINDOWS_SOCKET_COMMAND)
            if self._ok(result, "Windows listening socket inventory", errors):
                sockets = parse_windows_sockets(result.stdout)

        if self.config.include_connections:
            result = self.runner.run(WINDOWS_CONNECTION_COMMAND)
            if self._ok(
                result,
                "Windows outbound connection inventory",
                errors,
            ):
                if self.privacy_identity is None:
                    errors.append(
                        "Windows outbound privacy identity unavailable; "
                        "connections not persisted"
                    )
                else:
                    connections = parse_windows_connections(
                        result.stdout,
                        self.privacy_identity,
                        self.config.max_connection_records,
                    )

        if self.config.include_persistence:
            result = self.runner.run(WINDOWS_PERSISTENCE_COMMAND)
            if self._ok(result, "Windows persistence inventory", errors):
                if self.privacy_identity is None:
                    errors.append(
                        "Windows persistence privacy identity unavailable; "
                        "persistence records not stored"
                    )
                else:
                    persistence = parse_windows_persistence(
                        result.stdout,
                        self.privacy_identity,
                        self.config.max_persistence_entries,
                    )

        if self.config.include_docker:
            result = self.runner.run(DOCKER_PS_COMMAND)
            if self._ok(result, "Docker inventory", errors, optional=True):
                base = parse_docker_ps_output(
                    result.stdout,
                    namespace=self.config.data_identity_namespace,
                )
                ids = parse_docker_ps_ids(result.stdout)
                enriched = []
                for index, record in enumerate(base):
                    if (
                        index >= self.config.max_docker_inspects
                        or index >= len(ids)
                    ):
                        enriched.append(record)
                        continue
                    inspect = self.runner.run(
                        (*DOCKER_INSPECT_PREFIX, ids[index])
                    )
                    if self._ok(
                        inspect,
                        f"Docker inspect {record.name}",
                        errors,
                        optional=True,
                    ):
                        enriched.append(
                            parse_docker_inspect_output(
                                inspect.stdout,
                                record,
                            )
                        )
                    else:
                        enriched.append(record)
                containers = tuple(enriched)

        files = tuple(
            observe_file(path, self.config.max_file_hash_bytes)
            for path in self.config.sensitive_files
        )
        for record in files:
            if record.error:
                errors.append(
                    f"file observation {record.path}: {record.error}"
                )

        snapshot = CollectorSnapshot(
            observed_at=observed_at,
            host_id=self.host_id,
            processes=processes,
            sockets=sockets,
            containers=containers,
            files=files,
            errors=tuple(errors),
            collector_version="windows-read-only-v1",
            persistence=persistence,
            connections=connections,
            defender=defender,
        )
        events = list(
            retag_event_sources(
                diff_snapshots(snapshot, previous),
                old_prefix="debian_",
                new_prefix="windows_",
            )
        )

        if self.config.include_auth_events:
            result = self.runner.run(WINDOWS_AUTH_COMMAND)
            if self._ok(
                result,
                "Windows failed-logon event inventory",
                errors,
                optional=True,
            ):
                if self.privacy_identity is None:
                    errors.append(
                        "Windows authentication privacy identity unavailable; "
                        "failed-logon events not persisted"
                    )
                else:
                    events.extend(
                        parse_windows_auth_events(
                            result.stdout,
                            host_id=self.host_id,
                            privacy_identity=self.privacy_identity,
                            fallback_time=observed_at,
                        )
                    )

        snapshot = replace(snapshot, errors=tuple(errors))
        return CollectionBatch(snapshot, tuple(events))

    @staticmethod
    def _ok(
        result: CommandResult,
        label: str,
        errors: list[str],
        optional: bool = False,
    ) -> bool:
        if result.returncode == 0:
            return True
        prefix = "optional " if optional or result.returncode == 127 else ""
        detail = "timed out" if result.timed_out else f"exit code {result.returncode}"
        errors.append(f"{prefix}{label} unavailable: {detail}")
        return False
