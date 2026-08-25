#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any

REQUIRED_FILES = (
    Path("src/quietward/policy.py"),
    Path("src/quietward/config.py"),
    Path("src/quietward/storage.py"),
    Path("src/quietward/dashboard.py"),
    Path("src/quietward/collectors/command.py"),
    Path("src/quietward/collectors/windows_commands.py"),
    Path("src/quietward/collectors/windows_fast_core_command.py"),
    Path("src/quietward/collectors/windows_native_fast.py"),
    Path("src/quietward/scanners/execution.py"),
)

DISALLOWED_CALLS = {
    "os.system",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}

WINDOWS_MUTATION_TOKENS = (
    "stop-process", "stop-service", "start-service", "restart-service",
    "remove-item", "set-itemproperty", "new-itemproperty", "remove-itemproperty",
    "set-netfirewall", "new-netfirewall", "remove-netfirewall",
    "disable-netadapter", "enable-netadapter", "restart-computer", "stop-computer",
    "start-process", "invoke-webrequest", "invoke-restmethod",
)

NATIVE_WINDOWS_MUTATION_TOKENS = (
    "terminateprocess", "createprocess", "winexec", "shellexecute", "deletefile",
    "movefile", "setfileattributes", "writeprocessmemory", "createremotethread",
    "openservice", "controlservice", "changeserviceconfig", "regsetvalue", "regdelete",
    "setextendedtcptable", "setextendedudptable",
)


def _call_name(node: ast.Call) -> str:
    value = node.func
    parts: list[str] = []
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        parts.append(value.id)
    return ".".join(reversed(parts))


def _python_safety(root: Path, blockers: list[str]) -> int:
    files = 0
    source_root = root / "src" / "quietward"
    for path in sorted(source_root.rglob("*.py")):
        files += 1
        relative = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            blockers.append(f"cannot parse {relative}: {exc}")
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name in DISALLOWED_CALLS:
                blockers.append(f"forbidden execution API {name} in {relative}:{node.lineno}")
            if name == "subprocess.run":
                shell_values = [keyword.value for keyword in node.keywords if keyword.arg == "shell"]
                if not shell_values:
                    blockers.append(f"subprocess.run must explicitly set shell=False in {relative}:{node.lineno}")
                elif not all(isinstance(value, ast.Constant) and value.value is False for value in shell_values):
                    blockers.append(f"subprocess.run shell must remain false in {relative}:{node.lineno}")
    return files


def audit(root: Path) -> dict[str, Any]:
    checkout = root.resolve(strict=True)
    blockers: list[str] = []
    warnings: list[str] = []
    for relative in REQUIRED_FILES:
        if not (checkout / relative).is_file():
            blockers.append(f"missing safety-critical file: {relative.as_posix()}")
    files_checked = _python_safety(checkout, blockers)

    policy = (checkout / "src/quietward/policy.py").read_text(encoding="utf-8") if (checkout / "src/quietward/policy.py").is_file() else ""
    if 'mode = "observe_only"' not in policy:
        blockers.append("observation-only policy mode is missing")
    if "allowed=False" not in policy:
        blockers.append("observation-only policy does not explicitly deny actions")

    config = (checkout / "src/quietward/config.py").read_text(encoding="utf-8") if (checkout / "src/quietward/config.py").is_file() else ""
    if "only observe_only mode is supported" not in config:
        blockers.append("configuration does not fail closed to observe_only mode")

    storage = (checkout / "src/quietward/storage.py").read_text(encoding="utf-8") if (checkout / "src/quietward/storage.py").is_file() else ""
    if "CHECK(executable=0)" not in storage.replace(" ", ""):
        blockers.append("storage schema does not enforce executable proposals == 0")
    if "report.actions_executed != 0" not in storage:
        blockers.append("storage does not reject reports with executed actions")

    dashboard = (checkout / "src/quietward/dashboard.py").read_text(encoding="utf-8") if (checkout / "src/quietward/dashboard.py").is_file() else ""
    if "read-only dashboard" not in dashboard:
        blockers.append("dashboard read-only rejection path is missing")
    if "do_POST =" in dashboard:
        warnings.append("dashboard uses an unexpected do_POST alias; inspect manually")

    for relative in (
        Path("src/quietward/collectors/windows_commands.py"),
        Path("src/quietward/collectors/windows_fast_core_command.py"),
    ):
        path = checkout / relative
        if not path.is_file():
            continue
        lowered = path.read_text(encoding="utf-8").casefold()
        for token in WINDOWS_MUTATION_TOKENS:
            if token in lowered:
                blockers.append(f"Windows collector contains mutation/network primitive {token}: {relative.as_posix()}")

    native = checkout / "src/quietward/collectors/windows_native_fast.py"
    if native.is_file():
        lowered = native.read_text(encoding="utf-8").casefold()
        for token in NATIVE_WINDOWS_MUTATION_TOKENS:
            if token in lowered:
                blockers.append(f"native Windows FAST collector contains mutation primitive {token}")

    workflows = checkout / ".github" / "workflows"
    if workflows.exists() and any(path.is_file() for path in workflows.rglob("*")):
        blockers.append("GitHub Actions workflows are not permitted for this release line")

    return {
        "format": "quietward-v05-static-safety-audit-v1",
        "decision": "PASS" if not blockers else "FAIL",
        "files_checked": files_checked,
        "blockers": sorted(set(blockers)),
        "warnings": sorted(set(warnings)),
        "invariants": {
            "observation_only": True,
            "actions_executed": 0,
            "arbitrary_shell_execution": False,
            "automatic_remediation": False,
            "github_actions_used": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="statically audit QuietWard v0.5 observation-only safety invariants")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = audit(args.root)
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if result["decision"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
