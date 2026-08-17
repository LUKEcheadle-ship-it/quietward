from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Iterable

from .models import PersistenceRecord
from .privacy import redact_error, stable_hash

_DEFAULT_GLOBS = (
    "/etc/cron.d/*",
    "/etc/sudoers.d/*",
    "/etc/systemd/system/*.service",
    "/etc/systemd/system/*.timer",
    "/etc/systemd/system/*/*.service",
    "/etc/systemd/system/*/*.timer",
    "/var/spool/cron/crontabs/*",
)
_FIXED_FILES = (Path("/etc/crontab"), Path("/etc/profile"), Path("/etc/bash.bashrc"))
_INTERACTIVE_SHELLS = {"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/fish", "/usr/bin/bash", "/usr/bin/zsh", "/usr/bin/fish"}


def _fingerprint(parts: Iterable[object]) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8", errors="replace")).hexdigest()


def _read_text(path: Path, max_bytes: int) -> tuple[str | None, str | None]:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            return None, None
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            raw = os.read(descriptor, max_bytes + 1)
        finally:
            os.close(descriptor)
        if len(raw) > max_bytes:
            return None, "file exceeds persistence read limit"
        return raw.decode("utf-8", errors="replace"), None
    except FileNotFoundError:
        return None, None
    except PermissionError:
        # Per-user collection may not be able to inspect another account's
        # private startup files. Treat that optional observation as absent;
        # never turn a permissions boundary into a required collector failure.
        return None, None
    except OSError as exc:
        return None, redact_error(str(exc))


def _account_records(passwd_path: Path, group_path: Path, max_bytes: int, namespace: str) -> tuple[list[PersistenceRecord], list[str], list[Path]]:
    records: list[PersistenceRecord] = []
    errors: list[str] = []
    homes: list[Path] = []
    passwd, error = _read_text(passwd_path, max_bytes)
    if error:
        errors.append(f"account observation {passwd_path}: {error}")
    if passwd:
        for line in passwd.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name, _, uid_raw, gid_raw, _, home, shell = parts[:7]
            try:
                uid, gid = int(uid_raw), int(gid_raw)
            except ValueError:
                continue
            markers: set[str] = set()
            if uid == 0 and name != "root":
                markers.add("uid_zero_alias")
            if shell in _INTERACTIVE_SHELLS:
                markers.add("interactive_shell")
            if uid < 1000 and shell in _INTERACTIVE_SHELLS and name != "root":
                markers.add("interactive_system_account")
            if home.startswith("/"):
                homes.append(Path(home))
            records.append(PersistenceRecord(
                category="account",
                subject=f"user:{name[:100]}",
                fingerprint=_fingerprint((uid, gid, home, shell)),
                risk_markers=tuple(sorted(markers)),
                metadata={"uid": uid, "gid": gid, "home_hash": stable_hash(home, 16, namespace=namespace), "shell": shell[:120]},
            ))
    groups, error = _read_text(group_path, max_bytes)
    if error:
        errors.append(f"group observation {group_path}: {error}")
    if groups:
        for line in groups.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 4:
                continue
            name, _, gid_raw, members_raw = parts[:4]
            try:
                gid = int(gid_raw)
            except ValueError:
                continue
            members = tuple(sorted(item for item in members_raw.split(",") if item))
            markers = ("privileged_group_membership",) if name in {"sudo", "wheel", "docker", "adm"} and members else ()
            records.append(PersistenceRecord(
                category="group",
                subject=f"group:{name[:100]}",
                fingerprint=_fingerprint((gid, members)),
                risk_markers=markers,
                metadata={"gid": gid, "member_count": len(members), "members_hash": stable_hash("|".join(members), 16, namespace=namespace)},
            ))
    return records, errors, homes


def _artifact_record(path: Path, max_bytes: int) -> tuple[PersistenceRecord | None, str | None]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None, None
    except PermissionError:
        return None, None
    except OSError as exc:
        return None, redact_error(str(exc))
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        return None, None
    text, error = _read_text(path, max_bytes)
    if error:
        return None, error
    if text is None:
        return None, None
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    lowered = text.lower()
    markers: set[str] = set()
    category = "startup_file"
    path_text = str(path)
    if "authorized_keys" in path.name:
        category = "authorized_keys"
        if path_text.startswith("/root/"):
            markers.add("root_authorized_keys")
    elif "/cron" in path_text:
        category = "cron"
        markers.add("scheduled_persistence")
    elif path.suffix in {".service", ".timer"}:
        category = "systemd_unit"
        markers.add("service_persistence")
    elif "/sudoers" in path_text:
        category = "privilege_configuration"
        markers.add("privilege_configuration")
    if info.st_mode & stat.S_IWOTH:
        markers.add("world_writable")
    if any(prefix in lowered for prefix in ("/tmp/", "/var/tmp/", "/dev/shm/")):
        markers.add("volatile_path_reference")
    if ("curl " in lowered or "wget " in lowered) and ("| sh" in lowered or "| bash" in lowered):
        markers.add("download_execute_chain")
    if "/var/run/docker.sock" in lowered:
        markers.add("docker_socket_reference")
    key_count = 0
    if category == "authorized_keys":
        key_count = sum(1 for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))
    metadata = {
        "mode": stat.S_IMODE(info.st_mode),
        "owner_uid": info.st_uid,
        "owner_gid": info.st_gid,
        "size": info.st_size,
        "key_count": key_count,
        "raw_content_persisted": False,
    }
    return PersistenceRecord(category, path_text, digest, tuple(sorted(markers)), metadata), None


def observe_persistence(
    *,
    passwd_path: Path = Path("/etc/passwd"),
    group_path: Path = Path("/etc/group"),
    globs: tuple[str, ...] = _DEFAULT_GLOBS,
    max_entries: int = 500,
    max_file_bytes: int = 1_048_576,
    namespace: str = "quietward-v1",
) -> tuple[tuple[PersistenceRecord, ...], tuple[str, ...]]:
    if max_entries <= 0 or max_file_bytes <= 0:
        raise ValueError("persistence limits must be positive")
    records, errors, homes = _account_records(
        passwd_path, group_path, max_file_bytes, namespace
    )
    candidates: set[Path] = set(_FIXED_FILES)
    for pattern in globs:
        try:
            candidates.update(Path("/").glob(pattern.lstrip("/")))
        except (OSError, ValueError) as exc:
            errors.append(f"persistence glob {pattern}: {redact_error(str(exc))}")
    for home in homes[:200]:
        candidates.update((home / ".ssh" / "authorized_keys", home / ".profile", home / ".bashrc"))
    for path in sorted(candidates, key=lambda item: str(item)):
        if len(records) >= max_entries:
            errors.append("optional persistence inventory truncated at max_entries")
            break
        record, error = _artifact_record(path, max_file_bytes)
        if error:
            errors.append(f"optional persistence observation {path}: {error}")
        if record is not None:
            records.append(record)
    records.sort(key=lambda item: item.identity)
    return tuple(records[:max_entries]), tuple(dict.fromkeys(errors))
