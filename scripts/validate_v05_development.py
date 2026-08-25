#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Sequence

FOCUSED_TESTS = (
    "tests.test_windows_trusted_paths", "tests.test_release_paths_windows_trust", "tests.test_release_safety_blockers", "tests.test_scanner_execution", "tests.test_public_release", "tests.test_candidate_diagnostics", "tests.test_command_performance_metrics", "tests.test_docker_batch_performance", "tests.test_windows_listener_attribution", "tests.test_windows_collector_attribution", "tests.test_windows_persistence_context", "tests.test_windows_core_inventory", "tests.test_windows_core_performance_path", "tests.test_windows_native_fast", "tests.test_connections", "tests.test_connection_bounds", "tests.test_parsers", "tests.test_privacy_identity", "tests.test_scoring", "tests.test_v05_release_merge", "tests.test_coverage", "tests.test_source_coverage", "tests.test_cadence", "tests.test_cadenced_collector", "tests.test_cadenced_service", "tests.test_core_service", "tests.test_runtime_metrics", "tests.test_process_metrics", "tests.test_baseline", "tests.test_maintenance_store", "tests.test_compact_evidence_replay", "tests.test_operational_findings", "tests.test_alerts", "tests.test_user_status", "tests.test_console_status", "tests.test_retention_health", "tests.test_incident_export", "tests.test_build_sbom", "tests.test_runtime_benchmark", "tests.test_core_service_runtime_benchmark", "tests.test_performance_store", "tests.test_performance_store_hot_path", "tests.test_runtime_performance_store", "tests.test_freshness_performance_cache", "tests.test_integrity_performance", "tests.test_dashboard_performance", "tests.test_scoped_expected_rules", "tests.test_contextual_suppression_fail_closed", "tests.test_v05_safety_audit", "tests.test_finding_lifecycle", "tests.test_lifecycle_repository", "tests.test_source_aware_lifecycle", "tests.test_enhanced_dashboard", "tests.test_storage", "tests.test_service", "tests.test_service_coverage", "tests.test_service_lifecycle_wiring", "tests.test_service_health_recovery",
)

def _run(command: Sequence[str], *, root: Path, environment: dict[str, str]) -> dict[str, object]:
    completed = subprocess.run(tuple(command), cwd=root, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False, check=False)
    return {"command": list(command), "returncode": completed.returncode, "stdout": completed.stdout[-20000:], "stderr": completed.stderr[-20000:]}

def validate(root: Path) -> dict[str, object]:
    checkout = root.resolve(strict=True); environment = dict(os.environ); environment["PYTHONPATH"] = str(checkout / "src"); environment.setdefault("LANG", "C.UTF-8"); environment.setdefault("LC_ALL", "C.UTF-8")
    focused_tests = tuple(name for name in FOCUSED_TESTS if (checkout / (name.replace(".", "/") + ".py")).is_file()); missing = sorted(set(FOCUSED_TESTS) - set(focused_tests))
    if not focused_tests: raise RuntimeError("no focused v0.5 development tests are present")
    commands = ((sys.executable, "-m", "unittest", "-v", *focused_tests), (sys.executable, "-m", "compileall", "-q", "src", "tests", "scripts"))
    results = [_run(command, root=checkout, environment=environment) for command in commands]; decision = "PASS" if not missing and all(item["returncode"] == 0 for item in results) else "FAIL"
    return {"format": "quietward-v05-development-validation-v2", "decision": decision, "platform": sys.platform, "python": sys.version.split()[0], "focused_tests": list(focused_tests), "missing_tests": missing, "results": results, "windows_native_qualification_required": os.name != "nt", "actions_executed": 0}

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="run the bounded QuietWard v0.5 public development gate"); parser.add_argument("--root", type=Path, default=Path.cwd()); parser.add_argument("--pretty", action="store_true"); return parser.parse_args(argv)
def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv); result = validate(args.root); print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True)); return 0 if result["decision"] == "PASS" else 1
if __name__ == "__main__": raise SystemExit(main())
