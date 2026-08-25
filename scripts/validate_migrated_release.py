#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any, Sequence

EXPECTED_PROJECT = "quietward"
EXPECTED_PYTHON_VERSION = "0.5.0a1"


def _run(command: Sequence[str], *, root: Path, environment: dict[str, str]) -> dict[str, Any]:
    completed = subprocess.run(
        tuple(command), cwd=root, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False, check=False,
    )
    parsed: object = None
    if completed.stdout.strip():
        try:
            parsed = json.loads(completed.stdout)
        except json.JSONDecodeError:
            parsed = None
    return {
        "command": list(command),
        "returncode": completed.returncode,
        "result": parsed,
        "stdout_tail": completed.stdout[-20000:] if parsed is None else "",
        "stderr_tail": completed.stderr[-20000:],
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def validate(root: Path) -> dict[str, object]:
    checkout = root.expanduser().resolve(strict=True)
    pyproject_path = checkout / "pyproject.toml"
    try:
        project = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))["project"]
        project_name = str(project["name"])
        python_version = str(project["version"])
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        return {"format": "quietward-v05-migrated-release-gate-v1", "decision": "FAIL", "blockers": [f"cannot read migrated project metadata: {exc}"], "actions_executed": 0}

    blockers: list[str] = []
    if project_name != EXPECTED_PROJECT:
        blockers.append(f"migrated release project must be {EXPECTED_PROJECT}, found {project_name}")
    if python_version != EXPECTED_PYTHON_VERSION:
        blockers.append(f"migrated release version must be {EXPECTED_PYTHON_VERSION}, found {python_version}")
    if (checkout / "docs" / "V05_APPROVAL_PACKET.md").exists():
        blockers.append("private approval packet remained in migrated public tree")
    if (checkout / "NOTICE").exists():
        blockers.append("obsolete standalone NOTICE remained in migrated public tree")
    if blockers:
        return {"format": "quietward-v05-migrated-release-gate-v1", "decision": "FAIL", "project": project_name, "python_version": python_version, "blockers": blockers, "actions_executed": 0}

    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(checkout / "src")
    environment.setdefault("LANG", "C.UTF-8")
    environment.setdefault("LC_ALL", "C.UTF-8")

    results: list[dict[str, Any]] = []
    commands: tuple[tuple[str, ...], ...] = (
        (sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"),
        (sys.executable, "-m", "compileall", "-q", "src", "tests", "scripts"),
        (sys.executable, "scripts/audit_v05_safety.py", "--root", str(checkout), "--pretty"),
        (sys.executable, "scripts/public_release_audit.py", str(checkout)),
    )
    for command in commands:
        results.append(_run(command, root=checkout, environment=environment))

    with tempfile.TemporaryDirectory(prefix="quietward-v05-release-") as temporary:
        temporary_root = Path(temporary)
        first = temporary_root / "quietward-v0.5.0-alpha.1-first.zip"
        second = temporary_root / "quietward-v0.5.0-alpha.1-second.zip"
        for output in (first, second):
            results.append(_run((sys.executable, "scripts/build_release_bundle.py", str(output), "--root", str(checkout)), root=checkout, environment=environment))
        deterministic = first.is_file() and second.is_file() and _sha256(first) == _sha256(second)
        archive_sha256 = _sha256(first) if first.is_file() else None
        if first.is_file():
            results.append(_run((sys.executable, "scripts/verify_release_bundle.py", str(first)), root=checkout, environment=environment))
        if second.is_file():
            results.append(_run((sys.executable, "scripts/verify_release_bundle.py", str(second)), root=checkout, environment=environment))

    command_pass = all(item["returncode"] == 0 for item in results)
    decision = "PASS" if command_pass and deterministic else "FAIL"
    if not deterministic:
        blockers.append("deterministic release bundle comparison failed")

    return {
        "format": "quietward-v05-migrated-release-gate-v1",
        "decision": decision,
        "project": project_name,
        "python_version": python_version,
        "release_version": "0.5.0-alpha.1",
        "full_repository_tests_requested": True,
        "static_safety_audit_requested": True,
        "public_release_audit_requested": True,
        "deterministic_double_build_requested": True,
        "archive_verification_requested": True,
        "deterministic_builds_match": deterministic,
        "archive_sha256": archive_sha256,
        "results": results,
        "blockers": blockers,
        "ready_for_clean_public_branch": decision == "PASS",
        "release_authorized": False,
        "next_gate": "replay_tree_onto_clean_public_branch_then_run_platform_release_qualification" if decision == "PASS" else "fix_migrated_release_gate_failures",
        "safety": {"actions_executed": 0, "github_actions_used": False, "public_repository_modified_by_this_gate": False},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="validate a migrated QuietWard v0.5.0-alpha.1 release tree")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = validate(args.root)
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if result["decision"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
