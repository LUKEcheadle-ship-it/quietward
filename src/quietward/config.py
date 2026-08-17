from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any


_ALLOWED_TOP = {
    "mode",
    "state_dir",
    "collector",
    "storage",
    "service",
    "dashboard",
    "scanners",
    "tiny_model",
    "micro_llm",
    "self_integrity",
    "actions",
    "network",
}


def _unknown(value: dict[str, Any], allowed: set[str], section: str) -> None:
    extra = sorted(set(value) - allowed)
    if extra:
        raise ValueError(f"{section}: unknown field(s): {', '.join(extra)}")


def _object(value: Any, section: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{section} must be an object")
    return value


def _positive_int(value: Any, name: str, default: int) -> int:
    result = default if value is None else int(value)
    if result <= 0:
        raise ValueError(f"{name} must be positive")
    return result


def _positive_float(value: Any, name: str, default: float) -> float:
    result = default if value is None else float(value)
    if result <= 0:
        raise ValueError(f"{name} must be positive")
    return result


def _absolute_optional_path(value: Any, name: str) -> Path | None:
    if value in (None, ""):
        return None
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{name} must be absolute")
    return path


@dataclass(frozen=True, slots=True)
class CollectorSettings:
    interval_seconds: float = 60.0
    include_processes: bool = True
    include_listening_sockets: bool = True
    include_outbound_connections: bool = False
    include_auth_journal: bool = True
    include_docker: bool = True
    include_persistence: bool = True
    sensitive_files: tuple[Path, ...] = ()
    max_file_hash_bytes: int = 4 * 1024 * 1024
    max_persistence_entries: int = 500
    max_docker_inspects: int = 50
    privacy_identity_key_path: Path | None = None
    privacy_identity_namespace: str = "quietward-v1"
    data_identity_namespace: str = "quietward-v1"


@dataclass(frozen=True, slots=True)
class StorageSettings:
    database_path: Path
    alert_log_path: Path
    max_snapshots: int = 2000
    max_events: int = 100000
    max_findings: int = 25000
    retention_days: int = 30
    max_cycles: int = 2000
    max_scanner_runs: int = 10000
    evidence_signing_key_path: Path | None = None
    evidence_signing_key_namespace: str = "quietward-v1"


@dataclass(frozen=True, slots=True)
class ServiceSettings:
    health_path: Path
    lock_path: Path
    scanner_poll_seconds: float = 60.0
    stop_after_failures: int = 10


@dataclass(frozen=True, slots=True)
class DashboardSettings:
    enabled: bool = True
    bind: str = "127.0.0.1"
    port: int = 8765
    token_file: Path | None = None
    allow_private_network_bind: bool = False


@dataclass(frozen=True, slots=True)
class ScannerJobSettings:
    scanner: str
    enabled: bool
    interval_seconds: float
    timeout_seconds: float
    targets: tuple[Path, ...] = ()
    rules_path: Path | None = None
    suite: str | None = None
    data_source: Path | None = None
    max_output_bytes: int = 8_000_000
    max_data_age_hours: float | None = None


@dataclass(frozen=True, slots=True)
class TinyModelSettings:
    enabled: bool = False
    model_path: Path | None = None


@dataclass(frozen=True, slots=True)
class MicroLLMSettings:
    enabled: bool = False
    endpoint: str = "http://127.0.0.1:11434"
    model: str | None = None
    timeout_seconds: float = 20.0


@dataclass(frozen=True, slots=True)
class SelfIntegritySettings:
    enabled: bool = True
    extra_paths: tuple[Path, ...] = ()
    max_files: int = 1000
    max_file_bytes: int = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class SentinelConfig:
    state_dir: Path
    collector: CollectorSettings
    storage: StorageSettings
    service: ServiceSettings
    dashboard: DashboardSettings
    scanners: tuple[ScannerJobSettings, ...] = field(default_factory=tuple)
    tiny_model: TinyModelSettings = field(default_factory=TinyModelSettings)
    micro_llm: MicroLLMSettings = field(default_factory=MicroLLMSettings)
    self_integrity: SelfIntegritySettings = field(default_factory=SelfIntegritySettings)
    mode: str = "observe_only"
    config_path: Path | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SentinelConfig":
        _unknown(value, _ALLOWED_TOP, "config")
        mode = str(value.get("mode") or "observe_only")
        if mode != "observe_only":
            raise ValueError("only observe_only mode is supported")

        actions = _object(value.get("actions"), "actions")
        _unknown(actions, {"execute", "require_human_approval"}, "actions")
        if actions.get("execute") not in (None, False):
            raise ValueError("actions.execute must remain false")
        if actions.get("require_human_approval") is False:
            raise ValueError("actions.require_human_approval must remain true")

        network = _object(value.get("network"), "network")
        _unknown(network, {"cloud_upload", "public_listener"}, "network")
        if network.get("cloud_upload") not in (None, False):
            raise ValueError("network.cloud_upload must remain false")
        if network.get("public_listener") not in (None, False):
            raise ValueError("network.public_listener must remain false")

        state_dir = Path(
            str(value.get("state_dir") or "~/.local/state/quietward")
        ).expanduser()
        if not state_dir.is_absolute():
            raise ValueError("state_dir must resolve to an absolute path")

        raw_collector = _object(value.get("collector"), "collector")
        _unknown(
            raw_collector,
            {
                "type",
                "interval_seconds",
                "auth_journal_window_minutes",
                "include_processes",
                "include_listening_sockets",
                "include_outbound_connections",
                "include_auth_journal",
                "include_docker",
                "include_persistence",
                "sensitive_files",
                "max_file_hash_bytes",
                "max_persistence_entries",
                "max_docker_inspects",
                "persist_raw_process_arguments",
                "persist_raw_source_addresses",
                "persist_raw_destination_addresses",
                "use_shell",
                "use_sudo",
                "privacy_identity_key_path",
                "privacy_identity_namespace",
                "data_identity_namespace",
            },
            "collector",
        )
        if raw_collector.get("use_shell") not in (None, False) or raw_collector.get(
            "use_sudo"
        ) not in (None, False):
            raise ValueError("collector shell and sudo use must remain false")
        if (
            raw_collector.get("persist_raw_process_arguments") not in (None, False)
            or raw_collector.get("persist_raw_source_addresses") not in (None, False)
            or raw_collector.get("persist_raw_destination_addresses")
            not in (None, False)
        ):
            raise ValueError("raw sensitive collector fields may not be persisted")
        sensitive = tuple(
            Path(str(item)) for item in raw_collector.get("sensitive_files", [])
        )
        if any(not item.is_absolute() for item in sensitive):
            raise ValueError("collector.sensitive_files must contain absolute paths")
        collector = CollectorSettings(
            interval_seconds=_positive_float(
                raw_collector.get("interval_seconds"),
                "collector.interval_seconds",
                60.0,
            ),
            include_processes=bool(raw_collector.get("include_processes", True)),
            include_listening_sockets=bool(
                raw_collector.get("include_listening_sockets", True)
            ),
            include_outbound_connections=bool(
                raw_collector.get("include_outbound_connections", False)
            ),
            include_auth_journal=bool(
                raw_collector.get("include_auth_journal", True)
            ),
            include_docker=bool(raw_collector.get("include_docker", True)),
            include_persistence=bool(
                raw_collector.get("include_persistence", True)
            ),
            sensitive_files=sensitive,
            max_file_hash_bytes=_positive_int(
                raw_collector.get("max_file_hash_bytes"),
                "collector.max_file_hash_bytes",
                4 * 1024 * 1024,
            ),
            max_persistence_entries=_positive_int(
                raw_collector.get("max_persistence_entries"),
                "collector.max_persistence_entries",
                500,
            ),
            max_docker_inspects=_positive_int(
                raw_collector.get("max_docker_inspects"),
                "collector.max_docker_inspects",
                50,
            ),
            privacy_identity_key_path=_absolute_optional_path(
                raw_collector.get(
                    "privacy_identity_key_path",
                    "~/.config/quietward/privacy-identity.key",
                ),
                "collector.privacy_identity_key_path",
            ),
            privacy_identity_namespace=str(
                raw_collector.get("privacy_identity_namespace") or "quietward-v1"
            ),
            data_identity_namespace=str(
                raw_collector.get("data_identity_namespace") or "quietward-v1"
            ),
        )
        if collector.privacy_identity_namespace not in {
            "quietward-v1",
            "forge-sentinel-v1",
        }:
            raise ValueError("collector.privacy_identity_namespace is unsupported")
        if collector.data_identity_namespace not in {
            "quietward-v1",
            "forge-sentinel-v1",
        }:
            raise ValueError("collector.data_identity_namespace is unsupported")

        raw_storage = _object(value.get("storage"), "storage")
        _unknown(
            raw_storage,
            {
                "database_path",
                "alert_log_path",
                "max_snapshots",
                "max_events",
                "max_findings",
                "retention_days",
                "max_cycles",
                "max_scanner_runs",
                "evidence_signing_key_path",
                "evidence_signing_key_namespace",
            },
            "storage",
        )
        database_path = Path(
            str(raw_storage.get("database_path") or state_dir / "quietward.sqlite3")
        ).expanduser()
        alert_log_path = Path(
            str(raw_storage.get("alert_log_path") or state_dir / "alerts.jsonl")
        ).expanduser()
        if not database_path.is_absolute() or not alert_log_path.is_absolute():
            raise ValueError("storage paths must be absolute")
        storage = StorageSettings(
            database_path=database_path,
            alert_log_path=alert_log_path,
            max_snapshots=_positive_int(
                raw_storage.get("max_snapshots"), "storage.max_snapshots", 2000
            ),
            max_events=_positive_int(
                raw_storage.get("max_events"), "storage.max_events", 100000
            ),
            max_findings=_positive_int(
                raw_storage.get("max_findings"), "storage.max_findings", 25000
            ),
            retention_days=_positive_int(
                raw_storage.get("retention_days"), "storage.retention_days", 30
            ),
            max_cycles=_positive_int(
                raw_storage.get("max_cycles"), "storage.max_cycles", 2000
            ),
            max_scanner_runs=_positive_int(
                raw_storage.get("max_scanner_runs"),
                "storage.max_scanner_runs",
                10000,
            ),
            evidence_signing_key_path=_absolute_optional_path(
                raw_storage.get("evidence_signing_key_path"),
                "storage.evidence_signing_key_path",
            ),
            evidence_signing_key_namespace=str(
                raw_storage.get("evidence_signing_key_namespace") or "quietward-v1"
            ),
        )
        if storage.evidence_signing_key_namespace not in {
            "quietward-v1",
            "forge-sentinel-v1",
        }:
            raise ValueError("storage.evidence_signing_key_namespace is unsupported")

        raw_service = _object(value.get("service"), "service")
        _unknown(
            raw_service,
            {
                "health_path",
                "lock_path",
                "scanner_poll_seconds",
                "stop_after_failures",
            },
            "service",
        )
        service = ServiceSettings(
            Path(
                str(raw_service.get("health_path") or state_dir / "health.json")
            ).expanduser(),
            Path(
                str(raw_service.get("lock_path") or state_dir / "service.lock")
            ).expanduser(),
            _positive_float(
                raw_service.get("scanner_poll_seconds"),
                "service.scanner_poll_seconds",
                60.0,
            ),
            _positive_int(
                raw_service.get("stop_after_failures"),
                "service.stop_after_failures",
                10,
            ),
        )

        raw_dashboard = _object(value.get("dashboard"), "dashboard")
        _unknown(
            raw_dashboard,
            {
                "enabled",
                "bind",
                "port",
                "token_file",
                "allow_private_network_bind",
            },
            "dashboard",
        )
        port = int(raw_dashboard.get("port", 8765))
        if not 1 <= port <= 65535:
            raise ValueError("dashboard.port must be between 1 and 65535")
        dashboard = DashboardSettings(
            enabled=bool(raw_dashboard.get("enabled", True)),
            bind=str(raw_dashboard.get("bind") or "127.0.0.1"),
            port=port,
            token_file=_absolute_optional_path(
                raw_dashboard.get("token_file"),
                "dashboard.token_file",
            ),
            allow_private_network_bind=bool(
                raw_dashboard.get("allow_private_network_bind", False)
            ),
        )

        raw_scanners = value.get("scanners", [])
        if not isinstance(raw_scanners, list):
            raise ValueError("scanners must be a list")
        scanners: list[ScannerJobSettings] = []
        valid_scanners = {"clamav", "yara", "trivy", "debsecan"}
        for index, raw_item in enumerate(raw_scanners):
            item = _object(raw_item, f"scanners[{index}]")
            _unknown(
                item,
                {
                    "scanner",
                    "enabled",
                    "interval_seconds",
                    "timeout_seconds",
                    "targets",
                    "rules_path",
                    "suite",
                    "data_source",
                    "max_output_bytes",
                    "max_data_age_hours",
                },
                f"scanners[{index}]",
            )
            scanner = str(item.get("scanner") or "")
            if scanner not in valid_scanners:
                raise ValueError("invalid scanner")
            targets = tuple(
                Path(str(target)).expanduser() for target in item.get("targets", [])
            )
            rules_path = _absolute_optional_path(
                item.get("rules_path"),
                f"scanners[{index}].rules_path",
            )
            data_source = _absolute_optional_path(
                item.get("data_source"),
                f"scanners[{index}].data_source",
            )
            if any(not target.is_absolute() for target in targets):
                raise ValueError("scanner paths must be absolute")
            scanners.append(
                ScannerJobSettings(
                    scanner=scanner,
                    enabled=bool(item.get("enabled", False)),
                    interval_seconds=_positive_float(
                        item.get("interval_seconds"), "scanner interval", 86400
                    ),
                    timeout_seconds=_positive_float(
                        item.get("timeout_seconds"), "scanner timeout", 900
                    ),
                    targets=targets,
                    rules_path=rules_path,
                    suite=str(item["suite"]) if item.get("suite") else None,
                    data_source=data_source,
                    max_output_bytes=_positive_int(
                        item.get("max_output_bytes"),
                        "scanner max output",
                        8000000,
                    ),
                    max_data_age_hours=(
                        _positive_float(
                            item.get("max_data_age_hours"),
                            "scanner data age",
                            72,
                        )
                        if item.get("max_data_age_hours") is not None
                        else None
                    ),
                )
            )

        raw_tiny = _object(value.get("tiny_model"), "tiny_model")
        _unknown(raw_tiny, {"enabled", "model_path"}, "tiny_model")
        tiny_path = _absolute_optional_path(
            raw_tiny.get("model_path"),
            "tiny_model.model_path",
        )
        tiny = TinyModelSettings(bool(raw_tiny.get("enabled", False)), tiny_path)

        raw_llm = _object(value.get("micro_llm"), "micro_llm")
        _unknown(
            raw_llm,
            {"enabled", "endpoint", "model", "timeout_seconds"},
            "micro_llm",
        )
        llm = MicroLLMSettings(
            enabled=bool(raw_llm.get("enabled", False)),
            endpoint=str(raw_llm.get("endpoint") or "http://127.0.0.1:11434"),
            model=str(raw_llm["model"]) if raw_llm.get("model") else None,
            timeout_seconds=_positive_float(
                raw_llm.get("timeout_seconds"),
                "micro_llm.timeout_seconds",
                20,
            ),
        )
        if llm.enabled and not llm.model:
            raise ValueError("micro_llm.model is required when enabled")

        raw_integrity = _object(value.get("self_integrity"), "self_integrity")
        _unknown(
            raw_integrity,
            {"enabled", "extra_paths", "max_files", "max_file_bytes"},
            "self_integrity",
        )
        extra_paths = tuple(
            Path(str(item)).expanduser()
            for item in raw_integrity.get("extra_paths", [])
        )
        if any(not item.is_absolute() for item in extra_paths):
            raise ValueError("self_integrity.extra_paths must be absolute")
        integrity = SelfIntegritySettings(
            enabled=bool(raw_integrity.get("enabled", True)),
            extra_paths=extra_paths,
            max_files=_positive_int(
                raw_integrity.get("max_files"),
                "self_integrity.max_files",
                1000,
            ),
            max_file_bytes=_positive_int(
                raw_integrity.get("max_file_bytes"),
                "self_integrity.max_file_bytes",
                8 * 1024 * 1024,
            ),
        )
        return cls(
            state_dir,
            collector,
            storage,
            service,
            dashboard,
            tuple(scanners),
            tiny,
            llm,
            integrity,
            mode,
        )


QuietWardConfig = SentinelConfig


def load_config(path: Path) -> SentinelConfig:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load configuration {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("configuration root must be an object")
    return replace(
        SentinelConfig.from_dict(raw),
        config_path=path.expanduser().resolve(),
    )
