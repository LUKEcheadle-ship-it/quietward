#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence


def _run_json(command: Sequence[str], *, root: Path, environment: dict[str, str]) -> dict[str, Any]:
    completed = subprocess.run(tuple(command), cwd=root, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False, check=False)
    parsed: object = None
    if completed.stdout.strip():
        try: parsed = json.loads(completed.stdout)
        except json.JSONDecodeError: parsed = None
    return {"command": list(command), "returncode": completed.returncode, "result": parsed, "stdout_tail": completed.stdout[-4000:] if parsed is None else "", "stderr_tail": completed.stderr[-4000:]}

def run_campaign(root: Path, *, health: Path | None = None, runtime_config: Path | None = None, runtime_fast_samples: int = 5) -> dict[str, object]:
    checkout = root.resolve(strict=True); environment = dict(os.environ); environment["PYTHONPATH"] = str(checkout / "src"); environment.setdefault("LANG", "C.UTF-8"); environment.setdefault("LC_ALL", "C.UTF-8")
    gate = _run_json((sys.executable, "scripts/validate_core_development.py", "--pretty"), root=checkout, environment=environment)
    scaling = _run_json((sys.executable, "scripts/benchmark_core_scaling.py", "--history-rows", "25000", "--repetitions", "20", "--quiet-cycles", "60", "--pretty"), root=checkout, environment=environment)
    runtime_measurement: dict[str, Any] | None = None
    if runtime_config is not None:
        resolved_config = runtime_config.expanduser().resolve()
        runtime_measurement = _run_json((sys.executable, "scripts/benchmark_core_service_runtime.py", "--config", str(resolved_config), "--fast-samples", str(runtime_fast_samples), "--pretty"), root=checkout, environment=environment) if resolved_config.is_file() else {"command": [], "returncode": 2, "result": None, "stdout_tail": "", "stderr_tail": "runtime config file not found"}
    health_report: dict[str, Any] | None = None
    if health is not None:
        resolved_health = health.expanduser().resolve()
        health_report = _run_json((sys.executable, "scripts/report_core_health.py", str(resolved_health), "--pretty"), root=checkout, environment=environment) if resolved_health.is_file() else {"command": [], "returncode": 2, "result": None, "stdout_tail": "", "stderr_tail": "health file not found"}
    gate_result = gate.get("result"); gate_pass = gate["returncode"] == 0 and isinstance(gate_result, dict) and gate_result.get("decision") == "PASS"; scaling_pass = scaling["returncode"] == 0
    runtime_budget = None; runtime_execution_ok = runtime_measurement is None
    if runtime_measurement is not None:
        result = runtime_measurement.get("result"); runtime_execution_ok = isinstance(result, dict) and result.get("run_returncode") == 0
        if isinstance(result, dict): runtime_budget = (result.get("performance_budget") or {}).get("decision")
    health_budget = None
    if health_report is not None and isinstance(health_report.get("result"), dict): health_budget = (health_report["result"].get("performance_budget") or {}).get("decision")
    if not gate_pass or not scaling_pass or not runtime_execution_ok: decision = "FAIL"
    elif runtime_measurement is not None and runtime_budget != "PASS": decision = "ATTENTION"
    else: decision = "PASS"
    return {"format": "quietward-core-measurement-campaign-v2", "decision": decision, "core_gate": gate, "scaling_benchmark": scaling, "temporary_state_runtime_measurement": runtime_measurement, "runtime_performance_budget": runtime_budget, "live_health_report": health_report, "live_performance_budget": health_budget, "notes": ["PASS is an engineering checkpoint, not release authorization.", "When --runtime-config is supplied, the persistent service uses real wall-clock cycle spacing and temporary writable state.", "Optional scanners, micro-LLM, self-integrity, dashboard, and source writable state are disabled/redirected for the fast-profile measurement.", "A runtime budget miss is ATTENTION so the failing phase can be optimized rather than misreported as a passing target."], "safety": {"github_actions_used": False, "production_database_touched_by_scaling_benchmark": False, "runtime_measurement_uses_temporary_writable_state": runtime_measurement is not None, "release_published": False, "actions_executed": 0}}
def main() -> int:
    parser = argparse.ArgumentParser(description="run QuietWard core correctness, scaling, and optional live budget measurement"); parser.add_argument("--root", type=Path, default=Path.cwd()); parser.add_argument("--health", type=Path, default=None); parser.add_argument("--runtime-config", type=Path, default=None); parser.add_argument("--runtime-fast-samples", type=int, default=5); parser.add_argument("--pretty", action="store_true"); args = parser.parse_args()
    if not 5 <= args.runtime_fast_samples <= 20: raise ValueError("runtime-fast-samples must be between 5 and 20")
    result = run_campaign(args.root, health=args.health, runtime_config=args.runtime_config, runtime_fast_samples=args.runtime_fast_samples); print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True)); return 0 if result["decision"] == "PASS" else 1
if __name__ == "__main__": raise SystemExit(main())
