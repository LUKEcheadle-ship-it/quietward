from __future__ import annotations

import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import SentinelConfig
from .evidence import EvidenceSigner
from .freshness import ScannerFreshnessInspector
from .platforms import PlatformFamily, detect_platform, validate_collector_choice
from .privacy_identity import PrivacyIdentity


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    status: str
    details: str
    required: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "details": self.details,
            "required": self.required,
        }


def run_doctor(config: SentinelConfig) -> dict[str, Any]:
    platform_info = detect_platform()
    checks: list[DoctorCheck] = [
        DoctorCheck(
            "observe_only_mode",
            "PASS" if config.mode == "observe_only" else "FAIL",
            config.mode,
            True,
        ),
        DoctorCheck(
            "platform",
            "PASS"
            if platform_info.family is not PlatformFamily.UNSUPPORTED
            else "FAIL",
            (
                f"{platform_info.system} {platform_info.release}; "
                f"collector={platform_info.collector_name}"
            ),
            True,
        ),
        DoctorCheck(
            "state_parent",
            "PASS" if config.state_dir.parent.exists() else "WARN",
            str(config.state_dir.parent),
            False,
        ),
    ]
    try:
        validate_collector_choice(
            getattr(config.collector, "collector_type", "auto"),
            platform_info,
        )
    except ValueError as exc:
        checks.append(DoctorCheck("collector_selection", "FAIL", str(exc), True))
    else:
        checks.append(
            DoctorCheck(
                "collector_selection",
                "PASS",
                "platform-compatible read-only collector selected",
                True,
            )
        )
    checks.extend(_command_checks(config, platform_info.family))
    checks.append(_privacy_identity_check(config))
    checks.extend(_evidence_signing_checks(config))

    inspector = ScannerFreshnessInspector()
    freshness = [inspector.inspect(job).to_dict() for job in config.scanners]
    for status in freshness:
        if status["enabled"]:
            checks.append(
                DoctorCheck(
                    f"freshness:{status['scanner']}",
                    "FAIL" if status["stale"] else "PASS",
                    str(status["details"]),
                    True,
                )
            )
    checks.append(_database_check(config.storage.database_path))
    required_failures = [
        item.name for item in checks if item.required and item.status == "FAIL"
    ]
    return {
        "decision": "PASS" if not required_failures else "FAIL",
        "platform": {
            "family": platform_info.family.value,
            "system": platform_info.system,
            "release": platform_info.release,
            "distro_id": platform_info.distro_id,
            "distro_like": list(platform_info.distro_like),
            "systemd": platform_info.systemd,
        },
        "checks": [item.to_dict() for item in checks],
        "freshness": freshness,
        "required_failures": required_failures,
        "safety": {
            "actions_executed": 0,
            "shell_used": False,
            "sudo_used": False,
            "network_updates_performed": False,
            "system_state_modified": False,
        },
    }


def _privacy_identity_check(config: SentinelConfig) -> DoctorCheck:
    required = any(
        (
            config.collector.include_processes,
            config.collector.include_auth_journal,
            config.collector.include_persistence,
            config.collector.include_outbound_connections,
        )
    )
    if not required:
        return DoctorCheck(
            "privacy_identity",
            "PASS",
            "identity-bearing collectors disabled",
            False,
        )
    path = config.collector.privacy_identity_key_path
    if path is None:
        return DoctorCheck(
            "privacy_identity",
            "FAIL",
            "identity-bearing collectors require a privacy identity key",
            True,
        )
    try:
        PrivacyIdentity.load(
            path,
            namespace=config.collector.privacy_identity_namespace,
        )
    except ValueError as exc:
        return DoctorCheck("privacy_identity", "FAIL", str(exc), True)
    return DoctorCheck(
        "privacy_identity",
        "PASS",
        "installation-specific keyed identity is valid",
        True,
    )


def _command_checks(
    config: SentinelConfig,
    family: PlatformFamily,
) -> list[DoctorCheck]:
    values: list[DoctorCheck] = []
    if family is PlatformFamily.WINDOWS:
        commands = (
            ("powershell.exe", True),
            ("docker.exe", False),
        )
    elif family is PlatformFamily.LINUX:
        commands = (
            ("ps", config.collector.include_processes),
            (
                "ss",
                config.collector.include_listening_sockets
                or config.collector.include_outbound_connections,
            ),
            ("journalctl", config.collector.include_auth_journal),
            ("docker", False),
        )
    else:
        commands = ()
    for command, required in commands:
        available = shutil.which(command) is not None
        values.append(
            DoctorCheck(
                f"command:{command}",
                "PASS" if available else ("FAIL" if required else "WARN"),
                "available" if available else "not installed",
                required,
            )
        )
    for job in config.scanners:
        if job.enabled:
            binary = "clamscan" if job.scanner == "clamav" else job.scanner
            available = shutil.which(binary) is not None
            values.append(
                DoctorCheck(
                    f"scanner:{job.scanner}",
                    "PASS" if available else "FAIL",
                    "available" if available else "not installed",
                    True,
                )
            )
    return values


def _database_signing_key_id(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        connection = sqlite3.connect(
            f"file:{path}?mode=ro",
            uri=True,
            timeout=2.0,
        )
        try:
            row = connection.execute(
                "SELECT value FROM metadata "
                "WHERE key='evidence_signing_key_id'"
            ).fetchone()
        finally:
            connection.close()
        return str(row[0]) if row else None
    except sqlite3.Error:
        return None


def _evidence_signing_checks(config: SentinelConfig) -> list[DoctorCheck]:
    key_path = config.storage.evidence_signing_key_path
    database_key_id = _database_signing_key_id(config.storage.database_path)
    if key_path is None:
        if database_key_id is None:
            return [
                DoctorCheck(
                    "evidence_signing",
                    "WARN",
                    "disabled; retained evidence is hash-linked but unsigned",
                    False,
                )
            ]
        return [
            DoctorCheck(
                "evidence_signing",
                "FAIL",
                "database contains signed evidence but no signing key is configured",
                True,
            )
        ]
    try:
        signer = EvidenceSigner.load(
            key_path,
            key_id_namespace=config.storage.evidence_signing_key_namespace,
        )
    except (OSError, ValueError) as exc:
        return [
            DoctorCheck(
                "evidence_signing",
                "FAIL",
                str(exc)[:300],
                True,
            )
        ]
    if database_key_id is not None and database_key_id != signer.key_id:
        return [
            DoctorCheck(
                "evidence_signing",
                "FAIL",
                "configured signing key does not match the database",
                True,
            )
        ]
    return [
        DoctorCheck(
            "evidence_signing",
            "PASS",
            f"{signer.algorithm}; key id {signer.key_id}",
            True,
        )
    ]


def _database_check(path: Path) -> DoctorCheck:
    if not path.exists():
        return DoctorCheck(
            "database_integrity",
            "WARN",
            "database has not been created yet",
            False,
        )
    try:
        connection = sqlite3.connect(
            f"file:{path}?mode=ro",
            uri=True,
            timeout=2.0,
        )
        try:
            result = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        finally:
            connection.close()
        return DoctorCheck(
            "database_integrity",
            "PASS" if result == "ok" else "FAIL",
            result,
            True,
        )
    except sqlite3.Error as exc:
        return DoctorCheck(
            "database_integrity",
            "FAIL",
            str(exc)[:300],
            True,
        )
