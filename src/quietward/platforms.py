from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class PlatformFamily(StrEnum):
    LINUX = "linux"
    WINDOWS = "windows"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class PlatformInfo:
    family: PlatformFamily
    system: str
    release: str
    distro_id: str | None = None
    distro_like: tuple[str, ...] = ()
    systemd: bool = False

    @property
    def collector_name(self) -> str:
        if self.family is PlatformFamily.WINDOWS:
            return "windows"
        if self.family is PlatformFamily.LINUX:
            return "linux"
        return "unsupported"


def _parse_os_release(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        value = raw_value.strip().strip('"').strip("'")
        values[key.strip()] = value
    return values


def detect_platform(
    *,
    system_name: str | None = None,
    release: str | None = None,
    os_release_path: Path = Path("/etc/os-release"),
    systemd_path: Path = Path("/run/systemd/system"),
) -> PlatformInfo:
    system = (system_name or platform.system()).strip()
    detected_release = release or platform.release()
    lowered = system.lower()
    if lowered == "windows":
        return PlatformInfo(
            family=PlatformFamily.WINDOWS,
            system=system,
            release=detected_release,
        )
    if lowered == "linux":
        values = _parse_os_release(os_release_path)
        distro_id = values.get("ID", "unknown").strip().lower() or "unknown"
        like = tuple(
            item.strip().lower()
            for item in values.get("ID_LIKE", "").split()
            if item.strip()
        )
        return PlatformInfo(
            family=PlatformFamily.LINUX,
            system=system,
            release=detected_release,
            distro_id=distro_id,
            distro_like=like,
            systemd=systemd_path.exists(),
        )
    return PlatformInfo(
        family=PlatformFamily.UNSUPPORTED,
        system=system or "unknown",
        release=detected_release,
    )


def default_state_dir(info: PlatformInfo | None = None) -> Path:
    detected = info or detect_platform()
    if detected.family is PlatformFamily.WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / "QuietWard" / "state"
        return Path.home() / "AppData" / "Local" / "QuietWard" / "state"
    return Path("~/.local/state/quietward").expanduser()


def validate_collector_choice(requested: str, info: PlatformInfo) -> str:
    choice = (requested or "auto").strip().lower()
    valid = {"auto", "linux", "debian", "windows"}
    if choice not in valid:
        raise ValueError(f"unsupported collector type: {choice}")
    if choice == "auto":
        if info.family is PlatformFamily.WINDOWS:
            return "windows"
        if info.family is PlatformFamily.LINUX:
            return "debian" if info.distro_id == "debian" else "linux"
        raise ValueError(f"unsupported operating system: {info.system}")
    if choice in {"linux", "debian"} and info.family is not PlatformFamily.LINUX:
        raise ValueError(f"collector {choice} requires Linux")
    if choice == "windows" and info.family is not PlatformFamily.WINDOWS:
        raise ValueError("collector windows requires Windows")
    return choice
