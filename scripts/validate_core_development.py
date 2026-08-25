#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Sequence

CORE_TESTS = (
    "tests.test_scoring", "tests.test_cross_signal_correlation", "tests.test_temporal_context", "tests.test_v05_release_merge", "tests.test_coverage", "tests.test_source_coverage", "tests.test_cadence", "tests.test_cadenced_collector", "tests.test_cadenced_service", "tests.test_core_service", "tests.test_core_temporal_health", "tests.test_maintenance_governor", "tests.test_warm_start", "tests.test_runtime_metrics", "tests.test_process_metrics", "tests.test_performance_budget", "tests.test_health_io", "tests.test_baseline", "tests.test_maintenance_store", "tests.test_compact_evidence_replay", "tests.test_performance_store", "tests.test_performance_store_hot_path", "tests.test_runtime_performance_store", "tests.test_freshness_performance_cache", "tests.test_integrity_performance", "tests.test_lifecycle_repository", "tests.test_source_aware_lifecycle", "tests.test_lifecycle_scaling", "tests.test_core_store", "tests.test_operational_findings", "tests.test_scoped_expected_rules", "tests.test_contextual_suppression_fail_closed", "tests.test_alerts", "tests.test_user_status", "tests.test_dashboard_performance", "tests.test_enhanced_dashboard", "tests.test_retention_health", "tests.test_incident_export", "tests.test_storage", "tests.test_service", "tests.test_service_coverage", "tests.test_service_lifecycle_wiring", "tests.test_service_health_recovery", "tests.test_command_performance_metrics", "tests.test_docker_batch_performance", "tests.test_windows_fast_core_safety", "tests.test_windows_core_performance_path", "tests.test_windows_native_fast", "tests.test_runtime_benchmark", "tests.test_core_service_runtime_benchmark", "tests.test_core_health_report", "tests.test_v05_safety_audit",
)

def _run(command: Sequence[str], *, root: Path, environment: dict[str, str]) -> dict[str, object]:
    completed = subprocess.run(tuple(command), cwd=root, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False, check=False)
    return {"command": list(command), "returncode": completed.returncode, "stdout": completed.stdout[-40000:], "stderr": completed.stderr[-40000:]}

def validate(root: Path) -> dict[str, object]:
    checkout = root.resolve(strict=True); environment = dict(os.environ); environment["PYTHONPATH"] = str(checkout / "src"); environment.setdefault("LANG", "C.UTF-8"); environment.setdefault("LC_ALL", "C.UTF-8")
    present = tuple(name for name in CORE_TESTS if (checkout / (name.replace(".", "/") + ".py")).is_file()); missing = sorted(set(CORE_TESTS) - set(present))
    commands = [(sys.executable, "-m", "unittest", "-v", *present), (sys.executable, "-m", "compileall", "-q", "src", "tests", "scripts")]
    results = [_run(command, root=checkout, environment=environment) for command in commands]
    decision = "PASS" if not missing and all(item["returncode"] == 0 for item in results) else "FAIL"
    return {"format": "quietward-core-development-gate-v1", "decision": decision, "platform": sys.platform, "python": sys.version.split()[0], "tests": list(present), "missing_tests": missing, "results": results, "release_qualification": False, "platform_packaging_qualification": False, "actions_executed": 0}

def main() -> int:
    parser = argparse.ArgumentParser(description="run the QuietWard core-first focused engineering gate"); parser.add_argument("--root", type=Path, default=Path.cwd()); parser.add_argument("--pretty", action="store_true"); args = parser.parse_args(); result = validate(args.root); print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True)); return 0 if result["decision"] == "PASS" else 1
if __name__ == "__main__": raise SystemExit(main())
