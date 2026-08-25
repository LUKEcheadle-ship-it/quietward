#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import tempfile
from dataclasses import replace
from pathlib import Path

from quietward.config import load_config
from quietward.performance_budget import evaluate_performance_budget
from quietward.runtime import build_service


def _measurement_config(config_path: Path, state_dir: Path):
    source = load_config(config_path)
    root = state_dir.resolve()
    root.mkdir(parents=True, exist_ok=True)
    collector = replace(
        source.collector,
        privacy_identity_key_path=root / "privacy-identity.key",
    )
    storage = replace(
        source.storage,
        database_path=root / "measurement.sqlite3",
        alert_log_path=root / "alerts.jsonl",
        evidence_signing_key_path=root / "evidence-signing.key",
    )
    service = replace(
        source.service,
        health_path=root / "health.json",
        lock_path=root / "service.lock",
    )
    dashboard = replace(source.dashboard, enabled=False)
    scanners = tuple(replace(job, enabled=False) for job in source.scanners)
    micro_llm = replace(source.micro_llm, enabled=False)
    self_integrity = replace(source.self_integrity, enabled=False)
    return replace(
        source,
        state_dir=root,
        collector=collector,
        storage=storage,
        service=service,
        dashboard=dashboard,
        scanners=scanners,
        micro_llm=micro_llm,
        self_integrity=self_integrity,
        config_path=None,
    )


def _initialize_temporary_private_key(path: Path, *, label: str) -> None:
    """Create one benchmark-only private key without reading production key data."""
    if not path.is_absolute():
        raise ValueError(f"temporary {label} key path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        payload = os.urandom(64)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError(f"short temporary {label} key write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except Exception:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise


def _initialize_temporary_signing_key(path: Path) -> None:
    _initialize_temporary_private_key(path, label="evidence signing")


def _initialize_temporary_privacy_key(path: Path) -> None:
    _initialize_temporary_private_key(path, label="privacy identity")


def benchmark(config_path: Path, *, fast_samples: int = 5) -> dict[str, object]:
    if fast_samples < 5 or fast_samples > 20:
        raise ValueError("fast_samples must be between 5 and 20")
    resolved_config = config_path.expanduser().resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="quietward-core-measure-") as temporary:
        state_root = Path(temporary)
        config = _measurement_config(resolved_config, state_root)
        assert config.storage.evidence_signing_key_path is not None
        assert config.collector.privacy_identity_key_path is not None
        _initialize_temporary_signing_key(config.storage.evidence_signing_key_path)
        _initialize_temporary_privacy_key(config.collector.privacy_identity_key_path)
        service = build_service(config)
        run_code = 1
        try:
            run_code = service.run(max_cycles=fast_samples + 1)
            metrics = service.runtime_metrics.summary()
            budget = evaluate_performance_budget(metrics)
            maintenance = service.store.maintenance_state()
            evidence = service.store.verify_evidence_chain()
            health = json.loads(config.service.health_path.read_text(encoding="utf-8"))
            fast_profile = (metrics.get("profiles") or {}).get("fast") or {}
            result = {
                "format": "quietward-core-service-runtime-benchmark-v1",
                "run_returncode": run_code,
                "configured_fast_interval_seconds": config.collector.interval_seconds,
                "requested_fast_samples": fast_samples,
                "observed_fast_samples": int(fast_profile.get("samples", 0) or 0),
                "performance_budget": budget,
                "fast_profile": fast_profile,
                "latest_context": metrics.get("latest_context"),
                "maintenance": maintenance,
                "health_write": health.get("health_write"),
                "adaptive_maintenance": health.get("adaptive_maintenance"),
                "temporal_context": health.get("temporal_context"),
                "evidence_chain": {
                    "valid": bool(evidence.get("valid", False)),
                    "verification_mode": evidence.get("verification_mode"),
                    "cycles_checked": int(evidence.get("cycles_checked", 0) or 0),
                },
                "safety": {
                    "temporary_state_only": True,
                    "temporary_signing_key_initialized": True,
                    "temporary_privacy_key_initialized": True,
                    "production_signing_key_copied": False,
                    "production_privacy_key_copied": False,
                    "source_database_modified": False,
                    "source_alert_log_modified": False,
                    "source_health_file_modified": False,
                    "source_lock_file_modified": False,
                    "source_signing_key_modified": False,
                    "source_privacy_key_modified": False,
                    "configured_scanner_jobs_executed": 0,
                    "micro_llm_enabled": False,
                    "self_integrity_enabled_for_measurement": False,
                    "dashboard_enabled": False,
                    "actions_executed": 0,
                },
            }
            result["decision"] = "FAIL" if run_code != 0 else str(budget.get("decision") or "COLLECTING")
            return result
        finally:
            service.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="measure the real persistent QuietWard core with temporary writable state")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--fast-samples", type=int, default=5)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = benchmark(args.config, fast_samples=args.fast_samples)
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if result["decision"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
