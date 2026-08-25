from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, TypeVar

from .command import (
    DOCKER_INSPECT_PREFIX,
    DOCKER_PS_COMMAND,
    CommandResult,
    CommandRunner,
    ReadOnlyCommandRunner,
)
from .diff import diff_snapshots
from .docker_batch import parse_docker_inspect_batch_output
from .files import observe_file
from .models import CollectionBatch, CollectorSnapshot, ProcessRecord, SocketRecord
from .parsers import parse_docker_inspect_output, parse_docker_ps_ids, parse_docker_ps_output
from .privacy import derive_host_id
from .retag import retag_event_sources
from .windows_attribution import build_listener_attribution, enrich_listener_events
from .windows_commands import (
    WINDOWS_AUTH_COMMAND,
    WINDOWS_COMMANDS,
    WINDOWS_CONNECTION_COMMAND,
    WINDOWS_CORE_COMMAND,
    WINDOWS_DEFENDER_COMMAND,
    WINDOWS_PERSISTENCE_COMMAND,
    WINDOWS_PROCESS_COMMAND,
    WINDOWS_SOCKET_COMMAND,
)
from .windows_core import parse_windows_core_inventory
from .windows_fast_core_command import WINDOWS_FAST_CORE_COMMAND
from .windows_native_fast import WindowsNativeFastInventory, collect_windows_native_fast
from .windows_parsers import (
    parse_windows_auth_events,
    parse_windows_connections,
    parse_windows_defender,
    parse_windows_persistence,
    parse_windows_processes,
    parse_windows_sockets,
)
from ..privacy_identity import PrivacyIdentity

T = TypeVar("T")

_FAST_DETAIL_PROCESS_NAMES = frozenset({
    "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32",
    "regsvr32", "certutil", "vssadmin", "wmic", "wbadmin", "bcdedit", "wevtutil",
    "mimikatz", "procdump", "procdump64", "nc", "ncat", "netcat", "socat",
    "python", "pythonw", "node", "curl", "bitsadmin",
})


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
    refresh_slow_context: bool = True

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
        native_fast_collector: Callable[[], WindowsNativeFastInventory] = collect_windows_native_fast,
    ) -> None:
        self.config = config or WindowsCollectorConfig()
        self.runner = runner or ReadOnlyCommandRunner(
            timeout_seconds=20.0,
            additional_commands=(*WINDOWS_COMMANDS, WINDOWS_FAST_CORE_COMMAND),
        )
        self.host_id = host_id or derive_host_id(namespace=self.config.data_identity_namespace)
        self.native_fast_collector = native_fast_collector
        self.privacy_identity: PrivacyIdentity | None = None
        if (
            self.config.include_processes
            or self.config.include_connections
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

    @staticmethod
    def _usable(result: CommandResult) -> bool:
        return (
            result.returncode == 0
            and "[output truncated]" not in result.stdout
            and "[output truncated]" not in result.stderr
        )

    @staticmethod
    def _reuse_fast_process_context(
        processes: tuple[ProcessRecord, ...],
        previous: CollectorSnapshot | None,
    ) -> tuple[ProcessRecord, ...]:
        if previous is None or not previous.processes:
            return processes
        prior_by_pid = {item.pid: item for item in previous.processes}
        values: list[ProcessRecord] = []
        for item in processes:
            prior = prior_by_pid.get(item.pid)
            same_process = (
                prior is not None
                and prior.ppid == item.ppid
                and prior.command_name.casefold() == item.command_name.casefold()
                and prior.executable.casefold() == item.executable.casefold()
            )
            if not same_process:
                values.append(item)
                continue
            assert prior is not None
            changes: dict[str, object] = {}
            if item.user == "unavailable" and prior.user != "unavailable":
                changes["user"] = prior.user
                changes["privileged_context"] = prior.privileged_context
            if item.args_hash == "unavailable" and prior.args_hash != "unavailable":
                changes["args_hash"] = prior.args_hash
            values.append(replace(item, **changes) if changes else item)
        return tuple(values)

    @staticmethod
    def _process_stem(process: ProcessRecord) -> str:
        value = (process.executable or process.command_name).casefold()
        return value[:-4] if value.endswith(".exe") else value

    @classmethod
    def _fast_detail_needed(
        cls,
        processes: tuple[ProcessRecord, ...],
        sockets: tuple[SocketRecord, ...],
        previous: CollectorSnapshot | None,
    ) -> bool:
        if previous is None:
            return True
        prior_by_pid = {item.pid: item for item in previous.processes}
        for process in processes:
            prior = prior_by_pid.get(process.pid)
            changed = (
                prior is None
                or prior.ppid != process.ppid
                or prior.command_name.casefold() != process.command_name.casefold()
                or prior.executable.casefold() != process.executable.casefold()
            )
            if not changed:
                continue
            if process.suspicious_markers or cls._process_stem(process) in _FAST_DETAIL_PROCESS_NAMES:
                return True
        prior_sockets = {item.identity for item in previous.sockets}
        return any(item.identity not in prior_sockets for item in sockets)

    def _inspect_containers(self, base, ids, errors: list[str]):
        limit = min(len(base), len(ids), self.config.max_docker_inspects)
        if limit <= 0:
            return tuple(base)
        batch = self.runner.run((*DOCKER_INSPECT_PREFIX, *ids[:limit]))
        if self._ok(batch, "Docker inspect batch", errors, optional=True):
            enriched = list(parse_docker_inspect_batch_output(batch.stdout, base[:limit]))
            enriched.extend(base[limit:])
            return tuple(enriched)
        enriched = []
        for index, record in enumerate(base):
            if index >= limit:
                enriched.append(record)
                continue
            single = self.runner.run((*DOCKER_INSPECT_PREFIX, ids[index]))
            if self._ok(single, f"Docker inspect {record.name}", errors, optional=True):
                enriched.append(self._parse(
                    f"Docker inspect {record.name}",
                    lambda single=single, record=record: parse_docker_inspect_output(single.stdout, record),
                    errors,
                    record,
                ))
            else:
                enriched.append(record)
        return tuple(enriched)

    def collect(self, previous: CollectorSnapshot | None = None) -> CollectionBatch:
        observed_at = datetime.now(timezone.utc)
        errors: list[str] = []
        processes: tuple[ProcessRecord, ...] = ()
        sockets: tuple[SocketRecord, ...] = ()
        connections = ()
        persistence = ()
        containers = ()
        defender = previous.defender if previous is not None else None
        listener_attribution = {}
        native_socket_output = ""

        defender_done = not self.config.refresh_slow_context
        processes_done = not self.config.include_processes
        sockets_done = not self.config.include_sockets
        persistence_done = not self.config.include_persistence

        if not self.config.refresh_slow_context and (
            self.config.include_processes or self.config.include_sockets
        ):
            try:
                native = self.native_fast_collector()
            except (OSError, ValueError, AttributeError, TypeError):
                native = None
            if native is not None:
                native_socket_output = native.socket_output
                if self.config.include_processes and native.processes_ok:
                    processes = self._reuse_fast_process_context(native.processes, previous)
                    processes_done = True
                if self.config.include_sockets and native.sockets_ok:
                    sockets = native.sockets
                    sockets_done = True
                    listener_attribution = build_listener_attribution(native.socket_output, processes)
                if (
                    processes_done
                    and self.config.include_processes
                    and self._fast_detail_needed(processes, sockets, previous)
                ):
                    detail_result = self.runner.run(WINDOWS_PROCESS_COMMAND)
                    detail_errors: list[str] = []
                    if self._ok(detail_result, "optional Windows process detail", detail_errors, optional=True):
                        detailed = self._parse(
                            "optional Windows process detail",
                            lambda: parse_windows_processes(detail_result.stdout, self.privacy_identity),
                            detail_errors,
                            (),
                        )
                        if detailed:
                            processes = detailed
                            if sockets_done:
                                listener_attribution = build_listener_attribution(native.socket_output, processes)

        use_consolidated = (
            self.config.include_processes
            and self.config.include_sockets
            and (not processes_done or not sockets_done)
            and (not self.config.refresh_slow_context or self.config.include_persistence)
        )
        if use_consolidated:
            core_command = WINDOWS_CORE_COMMAND if self.config.refresh_slow_context else WINDOWS_FAST_CORE_COMMAND
            core_result = self.runner.run(core_command)
            if self._usable(core_result):
                core = self._parse(
                    "Windows consolidated full core inventory" if self.config.refresh_slow_context else "Windows consolidated fast core inventory",
                    lambda: parse_windows_core_inventory(
                        core_result.stdout,
                        self.privacy_identity,
                        max_persistence_entries=self.config.max_persistence_entries,
                    ),
                    [],
                    None,
                )
                if core is not None:
                    if core.defender_ok:
                        defender = core.defender
                        defender_done = True
                    if core.processes_ok:
                        processes = core.processes
                        if not self.config.refresh_slow_context:
                            processes = self._reuse_fast_process_context(processes, previous)
                        processes_done = True
                        if self.privacy_identity is None:
                            errors.append("Windows process privacy identity unavailable; account identities omitted")
                    if core.sockets_ok:
                        sockets = core.sockets
                        listener_attribution = core.listener_attribution
                        sockets_done = True
                    if self.config.include_persistence and core.persistence_ok:
                        persistence_done = True
                        if self.privacy_identity is None:
                            errors.append("Windows persistence privacy identity unavailable; persistence records not stored")
                        else:
                            persistence = core.persistence

        if self.config.refresh_slow_context and not defender_done:
            result = self.runner.run(WINDOWS_DEFENDER_COMMAND)
            if self._ok(result, "Microsoft Defender status", errors, optional=True):
                defender = self._parse("Microsoft Defender status", lambda: parse_windows_defender(result.stdout), errors, defender)

        if self.config.include_processes and not processes_done:
            result = self.runner.run(WINDOWS_PROCESS_COMMAND)
            if self._ok(result, "Windows process inventory", errors):
                if self.privacy_identity is None:
                    errors.append("Windows process privacy identity unavailable; account identities omitted")
                processes = self._parse(
                    "Windows process inventory",
                    lambda: parse_windows_processes(result.stdout, self.privacy_identity),
                    errors,
                    (),
                )
                if native_socket_output and sockets_done:
                    listener_attribution = build_listener_attribution(native_socket_output, processes)

        if self.config.include_sockets and not sockets_done:
            result = self.runner.run(WINDOWS_SOCKET_COMMAND)
            if self._ok(result, "Windows listening socket inventory", errors):
                sockets = self._parse("Windows listening socket inventory", lambda: parse_windows_sockets(result.stdout), errors, ())
                listener_attribution = self._parse(
                    "Windows listener process attribution",
                    lambda: build_listener_attribution(result.stdout, processes),
                    errors,
                    {},
                )

        if self.config.include_connections:
            result = self.runner.run(WINDOWS_CONNECTION_COMMAND)
            if self._ok(result, "Windows outbound connection inventory", errors):
                if self.privacy_identity is None:
                    errors.append("Windows outbound privacy identity unavailable; connections not persisted")
                else:
                    connections = self._parse(
                        "Windows outbound connection inventory",
                        lambda: parse_windows_connections(result.stdout, self.privacy_identity, self.config.max_connection_records),
                        errors,
                        (),
                    )

        if self.config.include_persistence and not persistence_done:
            result = self.runner.run(WINDOWS_PERSISTENCE_COMMAND)
            if self._ok(result, "Windows persistence inventory", errors):
                if self.privacy_identity is None:
                    errors.append("Windows persistence privacy identity unavailable; persistence records not stored")
                else:
                    persistence = self._parse(
                        "Windows persistence inventory",
                        lambda: parse_windows_persistence(result.stdout, self.privacy_identity, self.config.max_persistence_entries),
                        errors,
                        (),
                    )

        if self.config.include_docker:
            result = self.runner.run(DOCKER_PS_COMMAND)
            if self._ok(result, "Docker inventory", errors, optional=True):
                base = self._parse(
                    "Docker inventory",
                    lambda: parse_docker_ps_output(result.stdout, namespace=self.config.data_identity_namespace),
                    errors,
                    (),
                )
                ids = self._parse("Docker inventory identifiers", lambda: parse_docker_ps_ids(result.stdout), errors, ())
                containers = self._inspect_containers(base, ids, errors)

        files = tuple(observe_file(path, self.config.max_file_hash_bytes) for path in self.config.sensitive_files)
        for record in files:
            if record.error:
                errors.append(f"file observation {record.path}: {record.error}")

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
        events = list(retag_event_sources(diff_snapshots(snapshot, previous), old_prefix="debian_", new_prefix="windows_"))
        events = list(enrich_listener_events(events, listener_attribution))

        if self.config.include_auth_events:
            result = self.runner.run(WINDOWS_AUTH_COMMAND)
            if self._ok(result, "Windows failed-logon event inventory", errors, optional=True):
                if self.privacy_identity is None:
                    errors.append("Windows authentication privacy identity unavailable; failed-logon events not persisted")
                else:
                    events.extend(self._parse(
                        "Windows failed-logon event inventory",
                        lambda: parse_windows_auth_events(
                            result.stdout,
                            host_id=self.host_id,
                            privacy_identity=self.privacy_identity,
                            fallback_time=observed_at,
                        ),
                        errors,
                        (),
                    ))

        snapshot = replace(snapshot, errors=tuple(errors))
        return CollectionBatch(snapshot, tuple(events))

    @staticmethod
    def _parse(label: str, parser: Callable[[], T], errors: list[str], default: T) -> T:
        try:
            return parser()
        except (ValueError, TypeError, KeyError, IndexError):
            errors.append(f"{label} returned invalid or truncated data")
            return default

    @staticmethod
    def _ok(result: CommandResult, label: str, errors: list[str], optional: bool = False) -> bool:
        if result.returncode == 0:
            if "[output truncated]" in result.stdout or "[output truncated]" in result.stderr:
                prefix = "optional " if optional else ""
                errors.append(f"{prefix}{label} unavailable: output exceeded the safety limit")
                return False
            return True
        prefix = "optional " if optional or result.returncode == 127 else ""
        detail = "timed out" if result.timed_out else f"exit code {result.returncode}"
        errors.append(f"{prefix}{label} unavailable: {detail}")
        return False
