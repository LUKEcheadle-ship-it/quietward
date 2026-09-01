#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))


def _verify_no_execution_or_network_client() -> None:
    files = [
        ROOT / "src" / "quietward" / "integrations" / "response.py",
        ROOT / "scripts" / "export_response_handoff.py",
        ROOT / "scripts" / "run_response_handoff_outbox.py",
    ]
    forbidden = (
        "import subprocess",
        "from subprocess",
        "import socket",
        "from socket",
        "urllib.request",
        "requests.",
        "httpx.",
        "urlopen(",
        "os.system(",
        "shell=true",
        "actions_executed = 1",
        "executable_authority\": true",
    )
    for path in files:
        text = path.read_text(encoding="utf-8").lower()
        for marker in forbidden:
            if marker in text:
                raise RuntimeError(f"{path.relative_to(ROOT)} contains forbidden handoff capability: {marker}")


def main() -> int:
    _verify_no_execution_or_network_client()
    suite = unittest.defaultTestLoader.discover(
        str(ROOT / "tests"),
        pattern="test_response_handoff*.py",
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        return 1
    print("V0.6 RESPONSE HANDOFF GATE: PASS")
    print("QuietWard handoff remains local, sanitized, observation-only, and non-executable.")
    print("Continuous evidence-chain outbox: bounded and covered by the focused gate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
