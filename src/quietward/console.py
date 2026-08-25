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
from .config import StorageSettings, load_config
from .doctor import run_doctor
from .exports import build_redacted_incident_export, write_private_incident_export
from .lifecycle_repository import IncidentLifecycleRepository
from .operational_findings import current_findings
from .platforms import detect_platform
from .retention_health import assess_retention_health
from .storage import SentinelStore
from .support_context import lifecycle_context_for_finding
from .user_status import assess_user_status


def _decode_coverage(value: object) -> dict[str, Any] | None:
    if isinstance(value, dict):
        result = dict(value)
    elif isinstance(value, str) and value.strip():
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return None
        if not isinstance(decoded, dict):
            return None
        result = dict(decoded)
    else:
        return None
    result["actions_executed"] = 0
    return result


def _stored_coverage(store: object) -> dict[str, Any] | None:
    getter = getattr(store, "get_metadata", None)
    if not callable(getter):
        return None
    try:
        return _decode_coverage(getter("last_coverage_report"))
    except (OSError, TypeError, ValueError):
        return None


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
        connection = getattr(store, "connection", None)
        if connection is not None:
            bundle["lifecycle"] = lifecycle_context_for_finding(
                connection,
                args.finding_id,
            )
        stored_coverage = _stored_coverage(store)
        if stored_coverage is not None:
            bundle["coverage"] = stored_coverage

    service_settings = getattr(config, "service", None)
    health_path = getattr(service_settings, "health_path", None)
    if isinstance(health_path, Path):
        health, _ = _read_health(health_path)
        if isinstance(health, dict):
            current_coverage = _decode_coverage(health.get("coverage"))
            if current_coverage is not None:
                bundle["coverage"] = current_coverage

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


def _dashboard_host(bind: str) -> str:
    normalized = "127.0.0.1" if bind in {"0.0.0.0", "::"} else bind
    if ":" in normalized and not normalized.startswith("["):
        return f"[{normalized}]"
    return normalized


def _dashboard_request(url: str, token_file: Path | None) -> urllib.request.Request:
    request = urllib.request.Request(url)
    if token_file is not None:
        token = token_file.read_text(encoding="utf-8").strip()
        if len(token) < 24:
            raise ValueError("dashboard token must be at least 24 characters")
        request.add_header("Authorization", f"Bearer {token}")
    return request


def _run_open_dashboard(argv: Sequence[str]) -> int:
    args = _open_dashboard_parser().parse_args(argv)
    config = load_config(args.config)
    if not config.dashboard.enabled:
        raise ValueError("dashboard is disabled in configuration")
    host = _dashboard_host(config.dashboard.bind)
    url = f"http://{host}:{config.dashboard.port}/"
    health_url = f"http://{host}:{config.dashboard.port}/api/summary"
    available = False
    error: str | None = None
    try:
        request = _dashboard_request(health_url, config.dashboard.token_file)
        with urllib.request.urlopen(request, timeout=2.0) as response:
            available = response.status == 200
    except (OSError, ValueError, urllib.error.URLError) as exc:
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


def _status_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quietward status",
        description="show a plain-language local security status",
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument(
        "--stale-after-seconds",
        type=float,
        default=300.0,
        help="recommend review when monitoring is older than this many seconds",
    )
    return parser


def _run_status(argv: Sequence[str]) -> int:
    args = _status_parser().parse_args(argv)
    config = load_config(args.config)
    lifecycle_summary: dict[str, object] | None = None
    active_incidents: list[dict[str, object]] = []
    coverage: dict[str, Any] | None = None
    with SentinelStore(config.storage) as store:
        summary = store.summary()
        snapshot = store.latest_snapshot()
        coverage = _stored_coverage(store)
        connection = getattr(store, "connection", None)
        if connection is not None:
            lifecycle = IncidentLifecycleRepository(connection)
            lifecycle_summary = lifecycle.summary()
            active_incidents = lifecycle.recent_incidents(
                limit=20,
                active_only=True,
            )
            findings = current_findings(
                store,
                limit=500,
                active_only=True,
            )
        else:
            findings = store.recent_findings(500)

    service_settings = getattr(config, "service", None)
    health_path = getattr(service_settings, "health_path", None)
    if isinstance(health_path, Path):
        health, _ = _read_health(health_path)
        if isinstance(health, dict):
            current_coverage = _decode_coverage(health.get("coverage"))
            if current_coverage is not None:
                coverage = current_coverage

    retention: dict[str, object] | None = None
    if isinstance(config.storage, StorageSettings):
        retention = assess_retention_health(config.storage, summary).to_dict()

    collector_errors: tuple[str, ...] = ()
    defender: dict[str, Any] | None = None
    if snapshot is not None:
        collector_errors = tuple(snapshot.errors)
        defender = snapshot.defender.to_dict() if snapshot.defender else None
    assessment = assess_user_status(
        summary,
        findings,
        collector_errors=collector_errors,
        defender=defender,
        coverage=coverage,
        stale_after_seconds=args.stale_after_seconds,
    )
    result = {
        "status": assessment.to_dict(),
        "monitoring": {
            "last_cycle": summary.get("last_cycle"),
            "evidence_chain_valid": bool(
                (summary.get("evidence_chain") or {}).get("valid", False)
            ),
            "collector_warnings": list(collector_errors),
            "coverage": coverage,
            "retention": retention,
        },
        "incidents": {
            "summary": lifecycle_summary,
            "active": active_incidents,
        },
        "mode": "observe_only",
        "actions_executed": 0,
    }
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if assessment.level == "normal" else 1


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
    retention: dict[str, object] | None = None
    stored_coverage: dict[str, Any] | None = None
    try:
        with SentinelStore(config.storage) as store:
            storage = store.summary()
            stored_coverage = _stored_coverage(store)
        if storage is not None:
            retention = assess_retention_health(config.storage, storage).to_dict()
    except (OSError, ValueError) as exc:
        storage_error = str(exc)[:500]
    platform_info = detect_platform()
    evidence_valid = (
        storage is not None
        and bool((storage.get("evidence_chain") or {}).get("valid", False))
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
        "coverage": (
            _decode_coverage(health.get("coverage"))
            if isinstance(health, dict) and health.get("coverage") is not None
            else stored_coverage
        ),
        "retention": retention,
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
    if values and values[0] == "status":
        return _run_status(values[1:])
    if values and values[0] == "diagnose":
        return _run_diagnose(values[1:])
    return legacy_main(values)


if __name__ == "__main__":
    raise SystemExit(main())
