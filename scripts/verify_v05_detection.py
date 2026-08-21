#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(command: list[str]) -> None:
    print("\n>>>", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def _version() -> str:
    init_text = (ROOT / "src" / "quietward" / "__init__.py").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
    if match is None or match.group(1) != "0.5.0a1":
        raise RuntimeError("QuietWard detection branch must report 0.5.0a1")
    if 'version = "0.5.0a1"' not in pyproject:
        raise RuntimeError("pyproject version is not 0.5.0a1")
    return match.group(1)


def _verify_repository_separation() -> None:
    blocked = (
        "quietward-response",
        "response_client.py",
        "response_client_v11",
        "QWR_AGENT_",
    )
    findings: list[str] = []
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        path = ROOT / raw.decode("utf-8")
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if len(data) > 2_000_000 or b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for fragment in blocked:
            if fragment.lower() in text.lower() or fragment.lower() in path.as_posix().lower():
                findings.append(f"{path.relative_to(ROOT)}: {fragment}")
    if findings:
        raise RuntimeError(
            "QuietWard contains Response integration residue:\n" + "\n".join(sorted(set(findings)))
        )


def _verify_observation_only_source_contract() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    required = (
        "observation-only",
        "does not quarantine or delete files",
        "stop processes or services",
        "change firewall rules",
        "actions_executed == 0",
        "executable_proposals == 0",
    )
    missing = [item for item in required if item not in text]
    if missing:
        raise RuntimeError(f"observation-only README contract missing: {missing}")


def main() -> int:
    version = _version()
    _verify_repository_separation()
    _verify_observation_only_source_contract()
    _run([sys.executable, "-m", "compileall", "-q", "src", "tests"])
    _run([sys.executable, "-m", "pytest", "-q"])
    _run([sys.executable, "scripts/public_release_audit.py"])

    print("\nQUIETWARD 0.5.0-ALPHA.1 DETECTION GATE: PASS")
    print(f"version={version}")
    print("full pytest suite=PASS")
    print("cross-subject attack-chain correlation=PASS")
    print("credential-spray source/account aggregation=PASS")
    print("Windows reverse-shell/credential-dumping markers=PASS")
    print("Linux reverse-shell/downloader/encoded-shell markers=PASS")
    print("observation-only contract=PASS")
    print("Response repository/code separation=PASS")
    print("public-release audit=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
