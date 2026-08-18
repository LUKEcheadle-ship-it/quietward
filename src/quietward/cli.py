from __future__ import annotations

import argparse
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence

from .alerts import LocalAlertSink
from .collectors import CollectionBatch, CollectorSnapshot, DebianCollectorConfig, DebianReadOnlyCollector, build_collector
from .config import load_config
from .contracts import SecurityEvent
from .dashboard import DashboardServer
from .doctor import run_doctor
from .models import LinearPriorityModel
from .pipeline import SentinelPipeline
from .qualification import QualificationConfig, TargetHostQualifier
from .runtime import build_explainer, build_pipeline, build_service, bundled_model_path
from .scanners import ScannerExecutor, parse_clamav_output, parse_debsecan_simple, parse_trivy_json, parse_yara_output
from .storage import SentinelStore

DEFAULT_CONFIG = Path("~/.config/quietward/config.json").expanduser()


def load_events(path: Path) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
                if not isinstance(raw, dict):
                    raise ValueError("event row must be an object")
                events.append(SecurityEvent.from_dict(raw))
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
    return events


def load_snapshot(path: Path) -> CollectorSnapshot:
    try:
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load snapshot {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("snapshot file must contain a JSON object")
    if isinstance(raw.get("snapshot"), dict):
        raw = raw["snapshot"]
    return CollectorSnapshot.from_dict(raw)


def _config_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="quietward")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="analyze JSONL security events")
    analyze.add_argument("event_file", type=Path)
    analyze.add_argument("--pretty", action="store_true")
    collect = subparsers.add_parser("collect", help="collect one read-only Debian snapshot")
    collect.add_argument("--previous-snapshot", type=Path)
    collect.add_argument("--host-id")
    collect.add_argument("--file", action="append", type=Path, dest="files")
    collect.add_argument("--no-docker", action="store_true")
    collect.add_argument("--no-journal", action="store_true")
    collect.add_argument("--no-persistence", action="store_true")
    collect.add_argument("--pretty", action="store_true")
    ingest = subparsers.add_parser("ingest", help="normalize an existing scanner report")
    ingest.add_argument("scanner", choices=("clamav", "yara", "trivy", "debsecan"))
    ingest.add_argument("report_file", type=Path)
    ingest.add_argument("--host-id", required=True)
    ingest.add_argument("--target")
    ingest.add_argument("--scanner-exit-code", type=int)
    ingest.add_argument("--suite")
    ingest.add_argument("--pretty", action="store_true")
    qualify = subparsers.add_parser("qualify", help="run bounded target-host qualification")
    _config_argument(qualify)
    qualify.add_argument("--cycles", type=int, default=3)
    qualify.add_argument("--interval-seconds", type=float, default=1.0)
    qualify.add_argument("--max-cycle-ms", type=float, default=5000.0)
    qualify.add_argument("--max-snapshot-bytes", type=int, default=2_000_000)
    qualify.add_argument("--max-peak-rss-bytes", type=int, default=512 * 1024 * 1024)
    qualify.add_argument("--max-events-per-cycle", type=int, default=500)
    qualify.add_argument("--host-id")
    qualify.add_argument("--file", action="append", type=Path, dest="files")
    qualify.add_argument("--no-docker", action="store_true")
    qualify.add_argument("--no-journal", action="store_true")
    qualify.add_argument("--no-persistence", action="store_true")
    qualify.add_argument("--pretty", action="store_true")
    run = subparsers.add_parser("run", help="run the persistent observation-only service")
    _config_argument(run)
    run.add_argument("--cycles", type=int)
    run.add_argument("--no-dashboard", action="store_true")
    serve = subparsers.add_parser("serve", help="serve the read-only dashboard")
    _config_argument(serve)
    status = subparsers.add_parser("status", help="print service and storage status")
    _config_argument(status)
    status.add_argument("--pretty", action="store_true")
    doctor = subparsers.add_parser("doctor", help="validate prerequisites without modifying the host")
    _config_argument(doctor)
    doctor.add_argument("--pretty", action="store_true")
    scan = subparsers.add_parser("scan", help="run configured local scanners")
    _config_argument(scan)
    scan.add_argument("--scanner", choices=("clamav", "yara", "trivy", "debsecan"))
    scan.add_argument("--pretty", action="store_true")
    model_info = subparsers.add_parser("model-info", help="inspect the configured tiny model")
    _config_argument(model_info)
    model_info.add_argument("--pretty", action="store_true")
    incident = subparsers.add_parser("incident", help="manage finding state without modifying the host")
    _config_argument(incident)
    incident.add_argument("--pretty", action="store_true")
    incident_sub = incident.add_subparsers(dest="incident_action", required=True)
    incident_list = incident_sub.add_parser("list")
    incident_list.add_argument("--limit", type=int, default=100)
    for action in ("acknowledge", "resolve", "expected", "reopen"):
        command = incident_sub.add_parser(action)
        command.add_argument("finding_id")
        command.add_argument("--note")
    suppress = incident_sub.add_parser("suppress")
    suppress.add_argument("finding_id")
    suppress.add_argument("--minutes", type=int, required=True)
    suppress.add_argument("--note")
    incident_sub.add_parser("verify-chain")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        report = SentinelPipeline().analyze(load_events(args.event_file)).to_dict()
        print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
        return 0
    if args.command == "ingest":
        text = args.report_file.read_text(encoding="utf-8")
        if args.scanner == "clamav":
            events = parse_clamav_output(text, args.host_id, scanner_exit_code=args.scanner_exit_code)
        elif args.scanner == "yara":
            if not args.target:
                raise ValueError("--target is required for YARA reports")
            events = parse_yara_output(text, args.host_id, args.target)
        elif args.scanner == "trivy":
            events = parse_trivy_json(text, args.host_id)
        else:
            events = parse_debsecan_simple(text, args.host_id, suite=args.suite)
        result = {"scanner": args.scanner, "events": [event.to_dict() for event in events], "analysis": SentinelPipeline().analyze(events).to_dict(), "safety": {"adapter_only": True, "scanner_executed": False, "actions_executed": 0}}
        print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
        return 0
    if args.command == "qualify":
        config = load_config(args.config)
        overrides: dict[str, Any] = {}
        if args.files:
            overrides["sensitive_files"] = tuple(args.files)
        if args.no_docker:
            overrides["include_docker"] = False
        if args.no_journal:
            overrides["include_auth_journal"] = False
        if args.no_persistence:
            overrides["include_persistence"] = False
        settings = replace(config.collector, **overrides)
        collector = build_collector(settings, host_id=args.host_id)
        report = TargetHostQualifier(collector, QualificationConfig(cycles=args.cycles, interval_seconds=args.interval_seconds, max_cycle_ms=args.max_cycle_ms, max_snapshot_bytes=args.max_snapshot_bytes, max_peak_rss_bytes=args.max_peak_rss_bytes, max_events_per_cycle=args.max_events_per_cycle)).run().to_dict()
        print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
        return 0 if report["decision"] == "PASS" else 1
    if args.command == "collect":
        kwargs: dict[str, Any] = {"include_docker": not args.no_docker, "include_auth_journal": not args.no_journal, "include_persistence": not args.no_persistence}
        if args.files:
            kwargs["sensitive_files"] = tuple(args.files)
        collector = DebianReadOnlyCollector(config=DebianCollectorConfig(**kwargs), host_id=args.host_id)
        previous = load_snapshot(args.previous_snapshot) if args.previous_snapshot else None
        batch = collector.collect(previous)
        result = batch.to_dict()
        result["analysis"] = SentinelPipeline().analyze(list(batch.events)).to_dict()
        result["safety"] = {"collector_mode": "read_only", "actions_executed": 0, "shell_used": False, "sudo_used": False, "snapshot_written_by_process": False}
        print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
        return 0
    config = load_config(args.config)
    if args.command == "incident":
        with SentinelStore(config.storage) as store:
            action = args.incident_action
            if action == "list":
                result = {"findings": store.recent_findings(args.limit), "actions_executed": 0}
            elif action == "verify-chain":
                result = store.verify_evidence_chain()
            else:
                state = {"acknowledge": "acknowledged", "resolve": "resolved", "expected": "expected", "reopen": "open", "suppress": "suppressed"}[action]
                until = None
                if action == "suppress":
                    if args.minutes <= 0:
                        raise ValueError("--minutes must be positive")
                    until = datetime.now(timezone.utc) + timedelta(minutes=args.minutes)
                result = store.set_finding_state(args.finding_id, state, note=args.note, suppress_until=until, create_rule=action in {"expected", "suppress"})
        print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
        return 0 if result.get("valid", True) else 1
    if args.command == "doctor":
        result = run_doctor(config)
        print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
        return 0 if result["decision"] == "PASS" else 1
    if args.command == "status":
        health = json.loads(config.service.health_path.read_text(encoding="utf-8")) if config.service.health_path.exists() else None
        with SentinelStore(config.storage) as store:
            result = {"health": health, "storage": store.summary(), "actions_executed": 0}
        print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
        return 0
    if args.command == "serve":
        if not config.dashboard.enabled:
            raise ValueError("dashboard is disabled in configuration")
        server = DashboardServer(config.dashboard, config.storage)
        try:
            server.serve_forever()
        finally:
            server.httpd.server_close()
        return 0
    if args.command == "model-info":
        path = config.tiny_model.model_path or bundled_model_path()
        model = LinearPriorityModel.load(path)
        print(json.dumps({"path": str(path), "size_bytes": path.stat().st_size, "enabled": config.tiny_model.enabled, "model": model.to_dict()}, indent=2 if args.pretty else None, sort_keys=True))
        return 0
    if args.command == "scan":
        collector = DebianReadOnlyCollector()
        executor = ScannerExecutor(collector.host_id)
        selected = [job for job in config.scanners if job.enabled and (args.scanner is None or job.scanner == args.scanner)]
        if not selected:
            raise ValueError("no matching enabled scanner jobs")
        started = datetime.now(timezone.utc)
        all_events: list[SecurityEvent] = []
        runs: list[dict[str, Any]] = []
        with SentinelStore(config.storage) as store:
            for job in selected:
                for result in executor.run(job):
                    runs.append(result.to_dict())
                    all_events.extend(result.events)
                    store.record_scanner_run(result.to_dict())
            kept, suppressed = store.filter_suppressed_events(all_events, now=started)
            snapshot = store.latest_snapshot() or CollectorSnapshot(started, collector.host_id)
            report = build_pipeline(config).analyze(kept)
            store.persist_cycle(CollectionBatch(snapshot, tuple(kept)), report, started_at=started, completed_at=datetime.now(timezone.utc))
            alerts = LocalAlertSink(config.storage.alert_log_path, build_explainer(config)).emit_pending(store)
        print(json.dumps({"runs": runs, "events": [event.to_dict() for event in kept], "suppressed_events": len(suppressed), "analysis": report.to_dict(), "alerts_emitted": alerts, "actions_executed": 0}, indent=2 if args.pretty else None, sort_keys=True))
        return 0
    if args.command == "run":
        dashboard = None
        if config.dashboard.enabled and not args.no_dashboard:
            dashboard = DashboardServer(config.dashboard, config.storage)
            dashboard.start()
        service = build_service(config)
        try:
            return service.run(max_cycles=args.cycles)
        finally:
            service.close()
            if dashboard:
                dashboard.close()
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
