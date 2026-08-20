from __future__ import annotations

import argparse
import json
import os

import httpx

from .live_auth import AgentCredentials, run_stateful_auth_probes, run_stateless_auth_probes
from .matrix import CASES
from .runner import plan_results
from .scope import UnsafeTargetError, validate_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="QuietWard non-destructive adversarial validation harness")
    parser.add_argument("--target", default="http://127.0.0.1:8002", help="Loopback Response base URL")
    parser.add_argument("--list", action="store_true", help="List the current attack matrix")
    parser.add_argument("--auth-probes", action="store_true", help="Run six stateless HMAC/auth rejection probes")
    parser.add_argument("--stateful-auth-probes", action="store_true", help="Also create test-owned events for replay and UUID-conflict probes")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable output")
    return parser


def _credentials_from_env() -> AgentCredentials:
    names = {
        "agent_id": "QWA_AGENT_ID",
        "key_id": "QWA_KEY_ID",
        "secret": "QWA_SECRET",
        "host_id": "QWA_HOST_ID",
    }
    values = {field: os.environ.get(env_name, "").strip() for field, env_name in names.items()}
    missing = [env_name for field, env_name in names.items() if not values[field]]
    if missing:
        raise SystemExit("missing test-agent environment variables: " + ", ".join(missing))
    return AgentCredentials(**values)


def _render_results(results, *, as_json: bool) -> int:
    if as_json:
        print(json.dumps([
            {
                "case_id": result.case.case_id,
                "category": result.case.category,
                "verdict": result.verdict.value,
                "detail": result.detail,
                "evidence": result.evidence,
            }
            for result in results
        ], indent=2))
    else:
        for result in results:
            print(f"{result.case.case_id:14} {result.verdict.value:18} {result.case.title}")
    return 1 if any(result.verdict.value == "FAIL" for result in results) else 0


def main() -> int:
    args = build_parser().parse_args()
    try:
        scope = validate_target(args.target)
    except UnsafeTargetError as exc:
        raise SystemExit(f"unsafe target: {exc}") from exc

    if args.list:
        rows = [{
            "case_id": case.case_id,
            "category": case.category,
            "title": case.title,
            "expectation": case.expectation,
            "documented_limitation": case.documented_limitation,
        } for case in CASES]
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            for case in CASES:
                suffix = " [KNOWN LIMITATION]" if case.documented_limitation else ""
                print(f"{case.case_id:14} {case.category:20} {case.title}{suffix}")
        return 0

    if args.auth_probes or args.stateful_auth_probes:
        credentials = _credentials_from_env()
        with httpx.Client(base_url=scope.base_url, timeout=10.0) as client:
            results = run_stateless_auth_probes(client, credentials)
            if args.stateful_auth_probes:
                results.extend(run_stateful_auth_probes(client, credentials))
        return _render_results(results, as_json=args.json)

    return _render_results(plan_results(), as_json=args.json)


if __name__ == "__main__":
    raise SystemExit(main())
