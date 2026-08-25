#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from quietward.windows_restart import assess_windows_restart_state

try:
    import winreg
except ImportError:  # pragma: no cover - Windows-only command
    winreg = None  # type: ignore[assignment]

SESSION_MANAGER = r"SYSTEM\CurrentControlSet\Control\Session Manager"
CBS_PENDING = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
WU_PENDING = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
external_software_modified = False
PASS_DECISIONS = {"PASS", "PASS_STALE", "PASS_EXTERNAL"}


def key_exists(path: str) -> bool:
    assert winreg is not None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path):
            return True
    except FileNotFoundError:
        return False


def pending_values() -> list[str]:
    assert winreg is not None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SESSION_MANAGER) as key:
            value, value_type = winreg.QueryValueEx(key, "PendingFileRenameOperations")
    except FileNotFoundError:
        return []
    if value_type != winreg.REG_MULTI_SZ:
        return [str(value)]
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value]


def boot_token() -> str:
    uptime_ms = int(ctypes.windll.kernel32.GetTickCount64())
    boot_epoch_minutes = round((time.time() - (uptime_ms / 1000.0)) / 60.0)
    return str(boot_epoch_minutes)


def load_previous(path: Path | None) -> dict[str, object] | None:
    if path is None or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def atomic_write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect Windows restart state without modifying it")
    parser.add_argument("--history", type=Path)
    parser.add_argument("--write-report", type=Path, required=True)
    parser.add_argument("--show-paths", action="store_true")
    parser.add_argument(
        "--protected-root",
        action="append",
        default=[],
        help="QuietWard-owned root that must hard-block active queued operations; repeat as needed",
    )
    args = parser.parse_args()
    if sys.platform != "win32" or winreg is None:
        print(json.dumps({"decision": "BLOCK", "blockers": ["Windows is required"]}, indent=2))
        return 2
    previous = load_previous(args.history)
    result = assess_windows_restart_state(
        pending_values=pending_values(),
        component_servicing_pending=key_exists(CBS_PENDING),
        windows_update_pending=key_exists(WU_PENDING),
        system_root=os.environ.get("SystemRoot", r"C:\Windows"),
        boot_token=boot_token(),
        path_exists=os.path.exists,
        previous_report=previous,
        protected_roots=args.protected_root,
    )
    result["generated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    atomic_write(args.write_report, result)
    visible = dict(result)
    if not args.show_paths:
        visible["operations"] = [
            {
                "operation": item["operation"],
                "source_exists": item["source_exists"],
                "classification": item["classification"],
                "scope": item.get("scope"),
            }
            for item in result["operations"]
        ]
    print(json.dumps(visible, indent=2, sort_keys=True))
    return 0 if result["decision"] in PASS_DECISIONS else 2


if __name__ == "__main__":
    raise SystemExit(main())
