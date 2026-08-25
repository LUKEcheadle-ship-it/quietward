from __future__ import annotations

import hashlib
import json
import ntpath
import re
from collections.abc import Callable, Sequence
from typing import Any

_DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\/]")


def normalize_pending_path(value: str, *, system_root: str) -> str | None:
    """Convert common Session Manager NT paths into local Win32 paths."""
    path = value.strip()
    if not path:
        return None
    if len(path) >= 4 and path[:2] in {"*1", "*2"} and path[2] == "\\":
        path = path[2:]
    if path.startswith("!"):
        path = path[1:]
    lowered = path.lower()
    if lowered.startswith("\\??\\unc\\"):
        path = "\\\\" + path[8:]
    elif lowered.startswith("\\??\\"):
        path = path[4:]
    elif lowered.startswith("\\\\?\\unc\\"):
        path = "\\\\" + path[8:]
    elif lowered.startswith("\\\\?\\"):
        path = path[4:]
    elif lowered.startswith("\\systemroot\\"):
        path = system_root.rstrip("\\/") + "\\" + path[len("\\SystemRoot\\") :]
    if _DRIVE_PATH.match(path) or path.startswith("\\\\"):
        return path.replace("/", "\\")
    return None


def pending_pairs(values: Sequence[str]) -> list[tuple[str, str]]:
    raw = [str(item) for item in values]
    if len(raw) % 2:
        raw.append("")
    return [(raw[index], raw[index + 1]) for index in range(0, len(raw), 2)]


def pending_fingerprint(values: Sequence[str]) -> str:
    encoded = json.dumps(list(values), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalized_scope_path(value: str) -> str:
    return ntpath.normcase(ntpath.normpath(value.replace("/", "\\")))


def _path_is_within(path: str, root: str) -> bool:
    candidate = _normalized_scope_path(path)
    boundary = _normalized_scope_path(root).rstrip("\\")
    if not boundary:
        return False
    return candidate == boundary or candidate.startswith(boundary + "\\")


def _operation_scope(path: str, protected_roots: Sequence[str]) -> str:
    if not protected_roots:
        return "protected"
    return (
        "protected"
        if any(_path_is_within(path, root) for root in protected_roots if str(root).strip())
        else "external"
    )


def assess_windows_restart_state(
    *,
    pending_values: Sequence[str],
    component_servicing_pending: bool,
    windows_update_pending: bool,
    system_root: str,
    boot_token: str,
    path_exists: Callable[[str], bool],
    previous_report: dict[str, Any] | None = None,
    protected_roots: Sequence[str] = (),
) -> dict[str, Any]:
    """Classify reboot state without changing the registry or filesystem."""
    operations: list[dict[str, Any]] = []
    active = 0
    active_protected = 0
    active_external = 0
    stale = 0
    unknown = 0
    malformed = 0

    for source_raw, destination_raw in pending_pairs(pending_values):
        source = normalize_pending_path(source_raw, system_root=system_root)
        destination = normalize_pending_path(destination_raw, system_root=system_root) if destination_raw else None
        source_scope: str | None = None
        destination_scope: str | None = None
        scope: str | None = None
        if not source_raw.strip():
            malformed += 1
            classification = "malformed"
            source_exists = None
        elif source is None:
            unknown += 1
            classification = "unknown"
            source_exists = None
        else:
            source_scope = _operation_scope(source, protected_roots)
            if destination is not None:
                destination_scope = _operation_scope(destination, protected_roots)
            scope = "protected" if "protected" in {source_scope, destination_scope} else "external"
            try:
                source_exists = bool(path_exists(source))
            except OSError:
                source_exists = None
            if source_exists is True:
                active += 1
                classification = "active"
                if scope == "protected":
                    active_protected += 1
                else:
                    active_external += 1
            elif source_exists is False:
                stale += 1
                classification = "stale_candidate"
            else:
                unknown += 1
                classification = "unknown"
        operations.append({
            "operation": "delete" if not destination_raw else "rename",
            "source": source,
            "destination": destination,
            "source_exists": source_exists,
            "classification": classification,
            "scope": scope,
            "source_scope": source_scope,
            "destination_scope": destination_scope,
        })

    fingerprint = pending_fingerprint(pending_values)
    blockers: list[str] = []
    warnings: list[str] = []
    state = "clear"
    decision = "PASS"

    if component_servicing_pending:
        blockers.append("Component Based Servicing reports a pending restart")
    if windows_update_pending:
        blockers.append("Windows Update reports a pending restart")

    if operations:
        state = "pending_file_renames"
        if active_protected:
            blockers.append(f"{active_protected} active pending operation source(s) or destination(s) touch Sentinel-protected paths")
        if active_external:
            warnings.append(f"{active_external} active pending operation source(s) are external to Sentinel and were not modified")
        if unknown:
            blockers.append(f"{unknown} pending file operation source(s) could not be classified")
        if malformed:
            blockers.append(f"{malformed} pending file operation record(s) are malformed")

        hard_block = bool(component_servicing_pending or windows_update_pending or active_protected or unknown or malformed)
        if active_external and not hard_block:
            state = "external_host_maintenance_pending"
            decision = "PASS_EXTERNAL"
            if stale:
                warnings.append(f"{stale} additional absent-source operation(s) remain queued alongside external maintenance")
        elif stale and not hard_block:
            previous_fingerprint = str((previous_report or {}).get("pending_fingerprint", ""))
            previous_boot = str((previous_report or {}).get("boot_token", ""))
            previous_stale = int((previous_report or {}).get("counts", {}).get("stale_candidates", -1))
            previous_decision = str((previous_report or {}).get("decision", ""))
            exact_stale_set = previous_fingerprint == fingerprint and previous_stale == stale
            already_confirmed = exact_stale_set and previous_decision == "PASS_STALE"
            confirmed_across_boots = exact_stale_set and bool(previous_boot) and previous_boot != boot_token
            if already_confirmed or confirmed_across_boots:
                state = "confirmed_stale_pending_file_renames"
                decision = "PASS_STALE"
                warnings.append("The unchanged pending rename set contains only absent sources and was confirmed across distinct boots")
            else:
                decision = "STALE_CONFIRMATION_REQUIRED"
                blockers.append("Pending rename sources are absent, but the exact set must remain unchanged across a second distinct boot")

    if component_servicing_pending or windows_update_pending or active_protected or unknown or malformed:
        decision = "BLOCK"
    elif blockers and decision == "PASS":
        decision = "BLOCK"

    return {
        "format": "quietward-windows-restart-state-v2",
        "decision": decision,
        "state": state,
        "boot_token": boot_token,
        "component_servicing_pending": component_servicing_pending,
        "windows_update_pending": windows_update_pending,
        "pending_fingerprint": fingerprint,
        "counts": {
            "operations": len(operations),
            "active": active,
            "active_protected": active_protected,
            "active_external": active_external,
            "stale_candidates": stale,
            "unknown": unknown,
            "malformed": malformed,
        },
        "protected_roots_checked": len([root for root in protected_roots if str(root).strip()]),
        "operations": operations,
        "blockers": blockers,
        "warnings": warnings,
        "safety": {
            "registry_modified": False,
            "filesystem_modified": False,
            "external_software_modified": False,
            "actions_executed": 0,
        },
    }
