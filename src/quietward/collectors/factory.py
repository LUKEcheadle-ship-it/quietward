from __future__ import annotations

from ..config import CollectorSettings
from ..platforms import PlatformInfo, detect_platform, validate_collector_choice
from .base import ReadOnlyCollector
from .debian import DebianReadOnlyCollector
from .files import DEFAULT_SENSITIVE_FILES
from .linux import LinuxCollectorConfig, LinuxReadOnlyCollector
from .windows import WindowsCollectorConfig, WindowsReadOnlyCollector


def _linux_config(settings: CollectorSettings) -> LinuxCollectorConfig:
    return LinuxCollectorConfig(
        sensitive_files=settings.sensitive_files or DEFAULT_SENSITIVE_FILES,
        include_processes=settings.include_processes,
        include_sockets=settings.include_listening_sockets,
        include_connections=settings.include_outbound_connections,
        include_auth_journal=settings.include_auth_journal,
        include_docker=settings.include_docker,
        include_persistence=settings.include_persistence,
        max_file_hash_bytes=settings.max_file_hash_bytes,
        max_persistence_entries=settings.max_persistence_entries,
        max_docker_inspects=settings.max_docker_inspects,
        privacy_identity_key_path=settings.privacy_identity_key_path,
    )


def _windows_config(settings: CollectorSettings) -> WindowsCollectorConfig:
    return WindowsCollectorConfig(
        sensitive_files=settings.sensitive_files,
        include_processes=settings.include_processes,
        include_sockets=settings.include_listening_sockets,
        include_connections=settings.include_outbound_connections,
        include_auth_events=settings.include_auth_journal,
        include_docker=settings.include_docker,
        include_persistence=settings.include_persistence,
        max_file_hash_bytes=settings.max_file_hash_bytes,
        max_persistence_entries=settings.max_persistence_entries,
        max_docker_inspects=settings.max_docker_inspects,
        privacy_identity_key_path=settings.privacy_identity_key_path,
    )


def build_collector(
    settings: CollectorSettings,
    *,
    platform_info: PlatformInfo | None = None,
    runner=None,
    host_id: str | None = None,
) -> ReadOnlyCollector:
    info = platform_info or detect_platform()
    collector_type = validate_collector_choice(
        getattr(settings, "collector_type", "auto"),
        info,
    )
    if collector_type == "windows":
        return WindowsReadOnlyCollector(
            _windows_config(settings),
            runner=runner,
            host_id=host_id,
        )
    if collector_type == "debian":
        return DebianReadOnlyCollector(
            _linux_config(settings),
            runner=runner,
            host_id=host_id,
        )
    return LinuxReadOnlyCollector(
        _linux_config(settings),
        runner=runner,
        host_id=host_id,
        platform_info=info,
    )
