from __future__ import annotations

import hashlib
import os
import platform
from pathlib import Path


_NAMESPACE = b"quietward-v1"


def stable_hash(value: str, length: int = 20) -> str:
    digest = hashlib.sha256(
        _NAMESPACE + b"\x00" + value.encode("utf-8", errors="replace")
    ).hexdigest()
    return digest[:length]


def _windows_machine_id() -> str | None:
    if os.name != "nt":
        return None
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
        normalized = str(value).strip()
        return normalized or None
    except (OSError, ImportError):
        return None


def derive_host_id(
    machine_id_path: Path = Path("/etc/machine-id"),
) -> str:
    raw: str | None = None
    try:
        candidate = machine_id_path.read_text(encoding="utf-8").strip()
        raw = candidate or None
    except (OSError, UnicodeError):
        pass
    if raw is None:
        raw = _windows_machine_id()
    if raw is None:
        node = platform.node().strip()
        raw = node or f"unknown-{platform.system()}-{platform.machine()}"
    return "host-" + stable_hash(raw, 16)


def redact_error(value: str, limit: int = 300) -> str:
    single_line = " ".join(value.replace("\x00", "").split())
    return single_line[:limit] or "unspecified collector error"
