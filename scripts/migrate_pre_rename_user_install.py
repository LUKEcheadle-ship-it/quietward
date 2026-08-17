#!/usr/bin/env python3
"""Rollback-safe Forge Sentinel alpha to QuietWard user-install migration."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import tempfile
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence


LEGACY_NAMESPACE = "forge-sentinel-v1"
MIGRATION_VERSION = 1


@dataclass(frozen=True)
class Layout:
    home: Path

    @property
    def legacy_share(self) -> Path:
        return self.home / ".local/share/forge-sentinel"

    @property
    def legacy_config(self) -> Path:
        return self.home / ".config/forge-sentinel"

    @property
    def legacy_state(self) -> Path:
        return self.home / ".local/state/forge-sentinel"

    @property
    def legacy_unit(self) -> Path:
        return self.home / ".config/systemd/user/forge-sentinel.service"

    @property
    def quietward_share(self) -> Path:
        return self.home / ".local/share/quietward"

    @property
    def quietward_config(self) -> Path:
        return self.home / ".config/quietward"

    @property
    def quietward_state(self) -> Path:
        return self.home / ".local/state/quietward"

    @property
    def quietward_unit(self) -> Path:
        return self.home / ".config/systemd/user/quietward.service"

    @property
    def backup_root(self) -> Path:
        return self.home / ".local/state/quietward-migration-backups"


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _assert_under_home(path: Path, home: Path) -> None:
    resolved_home = home.resolve(strict=True)
    resolved_parent = path.parent.resolve(strict=True)
    if resolved_parent != resolved_home and resolved_home not in resolved_parent.parents:
        raise ValueError("migration path escapes the user home")


def _reject_symlinks(root: Path) -> None:
    if root.is_symlink():
        raise ValueError(f"refusing symlinked migration root: {root}")
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"refusing symlink in legacy installation: {path}")


def _private_file(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError(f"{label} must not be group/world accessible")


def _legacy_paths(layout: Layout) -> tuple[Path, ...]:
    return (
        layout.legacy_share,
        layout.legacy_config,
        layout.legacy_state,
        layout.legacy_unit,
    )


def validate_legacy(layout: Layout) -> None:
    for path in _legacy_paths(layout):
        _assert_under_home(path, layout.home)
        if not path.exists():
            raise ValueError(f"required legacy artifact is missing: {path}")
        if path.is_dir():
            _reject_symlinks(path)
        elif path.is_symlink() or not path.is_file():
            raise ValueError(f"legacy artifact is not a regular file: {path}")
    _private_file(layout.legacy_config / "privacy-identity.key", "privacy identity key")
    _private_file(layout.legacy_state / "evidence-signing.key", "evidence signing key")
    _private_file(layout.legacy_state / "sentinel.sqlite3", "legacy database")
    for target in (layout.quietward_share, layout.quietward_config, layout.quietward_state, layout.quietward_unit):
        if target.exists() or target.is_symlink():
            raise ValueError(f"QuietWard target already exists; migration safely rejected: {target}")


def _manifest(root: Path) -> None:
    records: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: str(item.relative_to(root))):
        relative = str(path.relative_to(root))
        info = path.lstat()
        record: dict[str, object] = {
            "path": relative,
            "mode": stat.S_IMODE(info.st_mode),
            "size": info.st_size,
            "type": "directory" if path.is_dir() else "file",
        }
        if path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            record["sha256"] = digest.hexdigest()
        records.append(record)
    output = root / "MANIFEST.json"
    output.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output.chmod(0o600)


def create_backup(layout: Layout) -> Path:
    layout.backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    layout.backup_root.chmod(0o700)
    backup = Path(tempfile.mkdtemp(prefix=f"{_utc()}-pre-rename-", dir=layout.backup_root))
    backup.chmod(0o700)
    legacy = backup / "legacy"
    legacy.mkdir(mode=0o700)
    shutil.copytree(layout.legacy_share, legacy / "share", copy_function=shutil.copy2)
    shutil.copytree(layout.legacy_config, legacy / "config", copy_function=shutil.copy2)
    shutil.copytree(layout.legacy_state, legacy / "state", copy_function=shutil.copy2)
    shutil.copy2(layout.legacy_unit, legacy / "forge-sentinel.service")
    _manifest(legacy)
    return backup


def _copy_database(source: Path, target: Path) -> None:
    with closing(sqlite3.connect(f"file:{source}?mode=ro", uri=True)) as src:
        if src.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("legacy database quick_check failed")
        schema = src.execute(
            "SELECT value FROM metadata WHERE key='schema_version'"
        ).fetchone()
        if schema is None or str(schema[0]) != "4":
            raise ValueError("only corrected legacy schema version 4 can be migrated")
        signing = src.execute(
            "SELECT value FROM metadata WHERE key='evidence_signing_key_id'"
        ).fetchone()
        if signing is None:
            raise ValueError("legacy database is not cryptographically signed")
        _validate_privacy_payloads(src)
        with closing(sqlite3.connect(target)) as dst:
            src.backup(dst)
            if dst.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("migrated database quick_check failed")
    target.chmod(0o600)


def _validate_privacy_payloads(connection: sqlite3.Connection) -> None:
    flags = {
        "raw_arguments_persisted",
        "raw_source_address_persisted",
        "raw_log_message_persisted",
        "raw_container_id_persisted",
        "raw_file_content_persisted",
        "raw_remote_address_persisted",
        "raw_local_address_persisted",
        "raw_persistence_content_persisted",
        "raw_authorized_keys_persisted",
        "raw_username_persisted",
    }

    def safe(value: object) -> bool:
        if isinstance(value, dict):
            return all(
                item is False if key in flags else safe(item)
                for key, item in value.items()
            )
        if isinstance(value, list):
            return all(safe(item) for item in value)
        return True

    for table in ("events", "findings", "snapshots", "evidence_chain"):
        for (raw,) in connection.execute(f'SELECT payload_json FROM "{table}"'):
            try:
                value = json.loads(str(raw))
            except json.JSONDecodeError as exc:
                raise ValueError(f"legacy {table} payload is invalid") from exc
            if not safe(value):
                raise ValueError(
                    "legacy database contains a persisted raw privacy field; archive it instead"
                )


def _migrated_config(layout: Layout) -> dict[str, object]:
    source = layout.legacy_config / "config.json"
    _private_file(source, "legacy configuration")
    value = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("legacy configuration must be an object")
    value["state_dir"] = str(layout.quietward_state)
    collector = value.setdefault("collector", {})
    storage = value.setdefault("storage", {})
    service = value.setdefault("service", {})
    if not all(isinstance(section, dict) for section in (collector, storage, service)):
        raise ValueError("legacy configuration sections are invalid")
    tiny_model = value.get("tiny_model") or {}
    if not isinstance(tiny_model, dict):
        raise ValueError("legacy tiny_model configuration is invalid")
    model_path = tiny_model.get("model_path")
    if model_path and layout.legacy_share in Path(str(model_path)).expanduser().parents:
        raise ValueError("legacy packaged model path cannot be migrated")
    collector["privacy_identity_key_path"] = str(layout.quietward_config / "privacy-identity.key")
    collector["privacy_identity_namespace"] = LEGACY_NAMESPACE
    collector["data_identity_namespace"] = LEGACY_NAMESPACE
    storage["database_path"] = str(layout.quietward_state / "quietward.sqlite3")
    storage["alert_log_path"] = str(layout.quietward_state / "alerts.jsonl")
    storage["evidence_signing_key_path"] = str(layout.quietward_state / "evidence-signing.key")
    storage["evidence_signing_key_namespace"] = LEGACY_NAMESPACE
    service["health_path"] = str(layout.quietward_state / "health.json")
    service["lock_path"] = str(layout.quietward_state / "service.lock")
    for job in value.get("scanners") or []:
        if not isinstance(job, dict):
            raise ValueError("legacy scanner configuration is invalid")
        if job.get("scanner") == "yara" and job.get("rules_path") == "/var/lib/forge-sentinel/yara/sentinel.yar":
            job["rules_path"] = "/var/lib/quietward/yara/quietward.yar"
        if job.get("scanner") == "debsecan" and job.get("data_source") == "/var/lib/forge-sentinel/debsecan/vulnerability-data.json":
            job["data_source"] = "/var/lib/quietward/debsecan/vulnerability-data.json"
    return value


def _verify_migrated_state(
    config_path: Path,
    migrated_state: Path,
    legacy_state: Path,
) -> dict[str, int]:
    import sys
    from dataclasses import replace

    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root / "src"))
    from quietward.config import load_config
    from quietward.storage import SentinelStore

    config = load_config(config_path)
    settings = replace(
        config.storage,
        database_path=migrated_state / "quietward.sqlite3",
        alert_log_path=migrated_state / "alerts.jsonl",
        evidence_signing_key_path=migrated_state / "evidence-signing.key",
    )
    with SentinelStore(settings) as store:
        chain = store.verify_evidence_chain()
        if not chain["valid"]:
            raise ValueError("legacy evidence verification failed")
        connection = store.connection
        counts = {
            name: int(connection.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0])
            for name in ("cycles", "findings", "finding_reviews", "evidence_chain", "evidence_signatures")
        }
    with closing(
        sqlite3.connect(f"file:{legacy_state / 'sentinel.sqlite3'}?mode=ro", uri=True)
    ) as source:
        for name, count in counts.items():
            original = int(source.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0])
            if original != count:
                raise ValueError(f"migrated {name} count changed")
    return counts


def prepare_migration(layout: Layout, *, require_inactive: bool = True) -> dict[str, object]:
    validate_legacy(layout)
    if require_inactive and _systemctl(("is-active", "--quiet", "forge-sentinel.service")).returncode == 0:
        raise ValueError("forge-sentinel.service must be inactive before migration")
    backup = create_backup(layout)
    config_parent = layout.quietward_config.parent
    state_parent = layout.quietward_state.parent
    config_parent.mkdir(parents=True, exist_ok=True)
    state_parent.mkdir(parents=True, exist_ok=True)
    staged_config = Path(tempfile.mkdtemp(prefix=".quietward-config-", dir=config_parent))
    staged_state = Path(tempfile.mkdtemp(prefix=".quietward-state-", dir=state_parent))
    committed_config = False
    try:
        staged_config.chmod(0o700)
        staged_state.chmod(0o700)
        shutil.copy2(layout.legacy_config / "privacy-identity.key", staged_config / "privacy-identity.key")
        (staged_config / "privacy-identity.key").chmod(0o600)
        config_path = staged_config / "config.json"
        config_path.write_text(json.dumps(_migrated_config(layout), indent=2) + "\n", encoding="utf-8")
        config_path.chmod(0o600)
        shutil.copy2(layout.legacy_state / "evidence-signing.key", staged_state / "evidence-signing.key")
        (staged_state / "evidence-signing.key").chmod(0o600)
        _copy_database(layout.legacy_state / "sentinel.sqlite3", staged_state / "quietward.sqlite3")
        alerts = layout.legacy_state / "alerts.jsonl"
        if alerts.exists():
            _private_file(alerts, "legacy alert log")
            shutil.copy2(alerts, staged_state / "alerts.jsonl")
            (staged_state / "alerts.jsonl").chmod(0o600)
        marker = {
            "migration_version": MIGRATION_VERSION,
            "source_product": "forge-sentinel",
            "source_namespace": LEGACY_NAMESPACE,
            "backup_directory": backup.name,
        }
        marker_path = staged_state / "pre-rename-migration.json"
        marker_path.write_text(json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        marker_path.chmod(0o600)
        counts = _verify_migrated_state(
            config_path,
            staged_state,
            layout.legacy_state,
        )
        staged_config.rename(layout.quietward_config)
        committed_config = True
        staged_state.rename(layout.quietward_state)
    except Exception:
        if committed_config and layout.quietward_config.exists():
            layout.quietward_config.rename(staged_config)
        shutil.rmtree(staged_config, ignore_errors=True)
        shutil.rmtree(staged_state, ignore_errors=True)
        raise
    return {"backup": str(backup), "counts": counts, "migration_version": MIGRATION_VERSION}


def _marker(layout: Layout) -> tuple[dict[str, object], Path]:
    path = layout.quietward_state / "pre-rename-migration.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("migration marker is unavailable")
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("migration_version") != MIGRATION_VERSION:
        raise ValueError("migration marker version is unsupported")
    backup = layout.backup_root / str(value.get("backup_directory") or "")
    if backup.parent != layout.backup_root or not backup.is_dir():
        raise ValueError("migration backup is unavailable")
    return value, backup


def rollback_prepared(layout: Layout) -> None:
    _, backup = _marker(layout)
    failed = backup / "failed-quietward-install"
    failed.mkdir(mode=0o700, exist_ok=True)
    for source, name in (
        (layout.quietward_share, "share"),
        (layout.quietward_config, "config"),
        (layout.quietward_state, "state"),
        (layout.quietward_unit, "quietward.service"),
    ):
        if source.exists() and not (failed / name).exists():
            source.rename(failed / name)


def _systemctl(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("systemctl", "--user", *args),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def finalize_migration(
    layout: Layout,
    *,
    systemctl: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] = _systemctl,
) -> Path:
    _, backup = _marker(layout)
    if systemctl(("is-active", "--quiet", "quietward.service")).returncode != 0:
        raise ValueError("quietward.service must be active before finalization")
    if systemctl(("is-enabled", "--quiet", "quietward.service")).returncode != 0:
        raise ValueError("quietward.service must be enabled before finalization")
    disabled = systemctl(("disable", "forge-sentinel.service"))
    if disabled.returncode != 0:
        raise ValueError("could not disable forge-sentinel.service")
    retired = backup / "retired-originals"
    retired.mkdir(mode=0o700, exist_ok=False)
    moved: list[tuple[Path, Path]] = []
    try:
        for source, name in (
            (layout.legacy_share, "share"),
            (layout.legacy_config, "config"),
            (layout.legacy_state, "state"),
            (layout.legacy_unit, "forge-sentinel.service"),
        ):
            if source.exists():
                target = retired / name
                source.rename(target)
                moved.append((source, target))
        systemctl(("daemon-reload",))
        if systemctl(("is-active", "--quiet", "forge-sentinel.service")).returncode == 0:
            raise ValueError("forge-sentinel.service remained active")
        if systemctl(("is-enabled", "--quiet", "forge-sentinel.service")).returncode == 0:
            raise ValueError("forge-sentinel.service remained enabled")
    except Exception:
        for source, target in reversed(moved):
            if target.exists() and not source.exists():
                target.rename(source)
        systemctl(("enable", "forge-sentinel.service"))
        systemctl(("daemon-reload",))
        raise
    return backup


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "finalize", "rollback"))
    args = parser.parse_args()
    layout = Layout(Path.home())
    try:
        if args.action == "prepare":
            print(json.dumps(prepare_migration(layout), sort_keys=True))
        elif args.action == "finalize":
            print(json.dumps({"backup": str(finalize_migration(layout))}, sort_keys=True))
        else:
            rollback_prepared(layout)
    except (OSError, ValueError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(f"QuietWard pre-rename migration failed: {exc}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
