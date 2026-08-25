#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

EXTRA_INTEGRATION_TESTS = (
    "tests.test_service_source_aware_wiring",
    "tests.test_contextual_suppression_fail_closed",
)

_SUMMARY_KEYS = (
    "format", "decision", "platform", "python", "actions_executed",
    "native_windows", "ready_for_public_replay", "run_returncode",
    "requested_fast_samples", "observed_fast_samples", "performance_budget",
    "fast_profile", "evidence_chain", "safety", "missing_tests", "missing_extra_tests",
)

def _parsed_summary(value: Any) -> dict[str, object] | None:
    if not isinstance(value, dict): return None
    return {key: value[key] for key in _SUMMARY_KEYS if key in value}

def _failure_excerpt(value: Any, *, limit: int = 16000) -> str:
    if not isinstance(value, dict): return ""
    nested = value.get("results")
    if not isinstance(nested, list): return ""
    excerpts: list[str] = []
    for item in nested:
        if not isinstance(item, dict) or int(item.get("returncode", 0) or 0) == 0: continue
        command = item.get("command"); stderr = str(item.get("stderr") or ""); stdout = str(item.get("stdout") or ""); detail = stderr or stdout
        excerpts.append("command=" + json.dumps(command, ensure_ascii=False) + "\n" + detail)
    return "\n\n".join(excerpts)[-limit:]

def _diagnostics_directory(checkout: Path, diagnostics_root: Path | None) -> Path:
    base = diagnostics_root.expanduser().resolve() if diagnostics_root is not None else Path(tempfile.gettempdir()).resolve()
    base.mkdir(parents=True, exist_ok=True)
    try: base.relative_to(checkout)
    except ValueError: pass
    else: raise ValueError("candidate diagnostics must be written outside the checkout")
    return Path(tempfile.mkdtemp(prefix="quietward-v05-candidate-", dir=str(base))).resolve()

def _run(command: Sequence[str], *, root: Path, environment: dict[str, str], diagnostics_dir: Path, stage: str) -> dict[str, object]:
    completed = subprocess.run(tuple(command), cwd=root, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False, check=False)
    stdout_path = diagnostics_dir / f"{stage}.stdout.log"; stderr_path = diagnostics_dir / f"{stage}.stderr.log"
    stdout_path.write_text(completed.stdout, encoding="utf-8", newline="\n"); stderr_path.write_text(completed.stderr, encoding="utf-8", newline="\n")
    parsed: Any = None
    if completed.stdout.strip():
        try: parsed = json.loads(completed.stdout)
        except json.JSONDecodeError: parsed = None
    return {"stage": stage, "command": list(command), "returncode": completed.returncode, "result_summary": _parsed_summary(parsed), "failure_excerpt": _failure_excerpt(parsed) if completed.returncode != 0 and parsed is not None else (completed.stderr or completed.stdout)[-16000:] if completed.returncode != 0 else "", "stdout_log": str(stdout_path), "stderr_log": str(stderr_path)}

def validate(root: Path, *, benchmark_config: Path | None = None, benchmark_cycles: int = 5, runtime_config: Path | None = None, runtime_fast_samples: int = 5, diagnostics_root: Path | None = None) -> dict[str, object]:
    checkout = root.resolve(strict=True); environment = dict(os.environ); environment["PYTHONPATH"] = str(checkout / "src"); environment.setdefault("LANG", "C.UTF-8"); environment.setdefault("LC_ALL", "C.UTF-8"); diagnostics_dir = _diagnostics_directory(checkout, diagnostics_root)
    commands: list[tuple[str, tuple[str, ...]]] = [
        ("core_development", (sys.executable, "scripts/validate_core_development.py", "--root", str(checkout), "--pretty")),
        ("v05_development", (sys.executable, "scripts/validate_v05_development.py", "--root", str(checkout), "--pretty")),
        ("static_safety", (sys.executable, "scripts/audit_v05_safety.py", "--root", str(checkout), "--pretty")),
        ("public_release_audit", (sys.executable, "scripts/public_release_audit.py", str(checkout))),
    ]
    present = tuple(name for name in EXTRA_INTEGRATION_TESTS if (checkout / (name.replace(".", "/") + ".py")).is_file())
    missing_extra = sorted(set(EXTRA_INTEGRATION_TESTS) - set(present))
    if present: commands.append(("extra_integration", (sys.executable, "-m", "unittest", "-v", *present)))
    commands.extend([("full_unittest_discovery", (sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v")), ("compileall", (sys.executable, "-m", "compileall", "-q", "src", "tests", "scripts"))])
    if benchmark_config is not None:
        resolved = benchmark_config.expanduser().resolve(strict=True); commands.append(("collector_benchmark", (sys.executable, "scripts/benchmark_v05_runtime.py", "--config", str(resolved), "--cycles", str(benchmark_cycles), "--pretty")))
    if runtime_config is not None:
        resolved_runtime = runtime_config.expanduser().resolve(strict=True); commands.append(("persistent_runtime_benchmark", (sys.executable, "scripts/benchmark_core_service_runtime.py", "--config", str(resolved_runtime), "--fast-samples", str(runtime_fast_samples), "--pretty")))
    results = [_run(command, root=checkout, environment=environment, diagnostics_dir=diagnostics_dir, stage=stage) for stage, command in commands]
    tests_pass = not missing_extra and all(item["returncode"] == 0 for item in results); native_windows = os.name == "nt"; runtime_measured = runtime_config is not None; ready_for_public_replay = tests_pass and native_windows and runtime_measured; failed_stages = [str(item["stage"]) for item in results if int(item["returncode"]) != 0]
    result = {
        "format": "quietward-v05-candidate-prequalification-v5", "decision": "PASS" if tests_pass else "FAIL", "platform": sys.platform, "python": sys.version.split()[0],
        "extra_integration_tests": list(present), "missing_extra_tests": missing_extra, "static_safety_audit_requested": True, "public_release_audit_requested": True, "full_repository_tests_requested": True,
        "collector_benchmark_requested": benchmark_config is not None, "collector_benchmark_cycles": benchmark_cycles if benchmark_config is not None else None,
        "persistent_runtime_benchmark_requested": runtime_measured, "persistent_runtime_fast_samples": runtime_fast_samples if runtime_measured else None,
        "native_windows": native_windows, "ready_for_public_replay": ready_for_public_replay, "public_release_authorized": False, "diagnostics_directory": str(diagnostics_dir), "failed_stages": failed_stages,
        "next_gate": "clean_public_replay_and_release_audit" if ready_for_public_replay else "inspect_failed_stage_diagnostics_and_rerun_exact_candidate", "results": results,
        "safety": {"github_actions_used": False, "actions_executed": 0, "release_published": False, "public_repository_modified": False, "diagnostics_written_outside_checkout": True, "automatic_retry_used": False},
    }
    (diagnostics_dir / "candidate-summary.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8", newline="\n")
    return result

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="run the frozen QuietWard v0.5 candidate gate"); parser.add_argument("--root", type=Path, default=Path.cwd()); parser.add_argument("--benchmark-config", type=Path); parser.add_argument("--benchmark-cycles", type=int, default=5); parser.add_argument("--runtime-config", type=Path, help="real host config used by the temporary-state persistent-service performance campaign; required for ready_for_public_replay"); parser.add_argument("--runtime-fast-samples", type=int, default=5); parser.add_argument("--diagnostics-root", type=Path, help="optional directory outside the checkout for persistent per-stage logs"); parser.add_argument("--pretty", action="store_true"); return parser.parse_args(argv)
def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv); result = validate(args.root, benchmark_config=args.benchmark_config, benchmark_cycles=args.benchmark_cycles, runtime_config=args.runtime_config, runtime_fast_samples=args.runtime_fast_samples, diagnostics_root=args.diagnostics_root); print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True)); return 0 if result["decision"] == "PASS" else 1
if __name__ == "__main__": raise SystemExit(main())
