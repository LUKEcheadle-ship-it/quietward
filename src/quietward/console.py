from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any, Sequence

from .cli import DEFAULT_CONFIG, main as legacy_main
from .config import load_config
from .doctor import run_doctor
from .exports import build_redacted_incident_export, write_private_incident_export
from .platforms import detect_platform
from .storage import SentinelStore


def _export_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quietward export",
        description="write a redacted local incident export",
    )
    parser.add_argument("finding_id")
    parser.add_argument("output", type=Path)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        dest="output_format",
    )
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    return parser


def _run_export(argv: Sequence[str]) -> int:
    args = _export_parser().parse_args(argv)
    config = load_config(args.config)
    with SentinelStore(config.storage) as store:
        bundle = store.incident_bundle(args.finding_id)
    redacted = build_redacted_incident_export(bundle)
    result = write_private_incident_export(
        args.output,
        redacted,
        output_format=args.output_format,
        force=args.force,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0


def _open_dashboard_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quietward open-dashboard",
        description="open the local read-only QuietWard dashboard",
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    return parser


def _run_open_dashboard(argv: Sequence[str]) -> int:
    args = _open_dashboard_parser().parse_args(argv)
    config = load_config(args.config)
    if not config.dashboard.enabled:
        raise ValueError("dashboard is disabled in configuration")
    bind = config.dashboard.bind
    if bind in {"0.0.0.0", "::"}:
        bind = "127.0.0.1"
    url = f"http://{bind}:{config.dashboard.port}/"
    health_url = f"http://{bind}:{config.dashboard.port}/api/summary"
    available = False
    error: str | None = None
    try:
        with urllib.request.urlopen(health_url, timeout=2.0) as response:
            available = response.status == 200
    except (OSError, urllib.error.URLError) as exc:
        error = str(exc)[:300]
    result = {
        "url": url,
        "dashboard_available": available,
        "opened_browser": False,
        "error": error,
        "actions_executed": 0,
    }
    if available and not args.no_browser:
        result["opened_browser"] = bool(webbrowser.open(url))
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if available else 1


def _diagnose_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quietward diagnose",
        description="collect a read-only health and usability diagnostic",
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--pretty", action="store_true")
    return parser


def _read_health(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, "service health file does not exist"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"cannot read service health: {exc}"
    if not isinstance(value, dict):
        return None, "service health is not a JSON object"
    return value, None


def _run_diagnose(argv: Sequence[str]) -> int:
    args = _diagnose_parser().parse_args(argv)
    config = load_config(args.config)
    doctor = run_doctor(config)
    health, health_error = _read_health(config.service.health_path)
    storage: dict[str, Any] | None = None
    storage_error: str | None = None
    try:
        with SentinelStore(config.storage) as store:
            storage = store.summary()
    except (OSError, ValueError) as exc:
        storage_error = str(exc)[:500]
    platform_info = detect_platform()
    evidence_valid = (
        storage is not None
        and bool((storage.get("evidence_chain") or {}).get("valid", True))
    )
    service_healthy = health is not None and health.get("status") in {
        "healthy",
        "starting",
    }
    decision = (
        "PASS"
        if doctor.get("decision") == "PASS"
        and evidence_valid
        and service_healthy
        and storage_error is None
        else "ATTENTION"
    )
    result = {
        "decision": decision,
        "platform": {
            "family": platform_info.family.value,
            "system": platform_info.system,
            "release": platform_info.release,
            "distro_id": platform_info.distro_id,
        },
        "doctor": doctor,
        "service_health": health,
        "service_health_error": health_error,
        "storage": storage,
        "storage_error": storage_error,
        "next_steps": [
            "Start QuietWard if the service health file is missing or stopped.",
            "Open the dashboard and review open high or critical findings.",
            "Review collector errors before changing system configuration.",
        ],
        "actions_executed": 0,
    }
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if decision == "PASS" else 1


def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if values and values[0] == "export":
        return _run_export(values[1:])
    if values and values[0] == "open-dashboard":
        return _run_open_dashboard(values[1:])
    if values and values[0] == "diagnose":
        return _run_diagnose(values[1:])
    return legacy_main(values)


if __name__ == "__main__":
    raise SystemExit(main())
