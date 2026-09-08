#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from quietward.contracts import EventKind, SecurityEvent
from quietward.pipeline import SentinelPipeline


def build_demo_events(observed_at: datetime | None = None) -> list[SecurityEvent]:
    """Return deterministic synthetic events without reading or modifying the host."""
    base = observed_at or datetime.now(timezone.utc)
    if base.tzinfo is None or base.utcoffset() is None:
        raise ValueError("demo timestamp must be timezone-aware")

    return [
        SecurityEvent(
            event_id="demo-malware-signature",
            observed_at=base,
            host_id="quietward-demo-host",
            source="quietward_demo",
            kind=EventKind.MALWARE_SIGNATURE,
            subject="/demo/suspicious-payload.bin",
            attributes={
                "known_bad_hash": True,
                "scanner": "synthetic-demo",
                "synthetic": True,
            },
            confidence=1.0,
        ),
        SecurityEvent(
            event_id="demo-credential-spray",
            observed_at=base + timedelta(seconds=1),
            host_id="quietward-demo-host",
            source="quietward_demo",
            kind=EventKind.AUTH_FAILURE,
            subject="auth-source:demo-pseudonym",
            attributes={
                "failed_count": 32,
                "source_failed_count": 32,
                "distinct_accounts": 8,
                "suspicious_markers": ["credential_spray"],
                "synthetic": True,
            },
            confidence=0.95,
        ),
        SecurityEvent(
            event_id="demo-reverse-shell-behavior",
            observed_at=base + timedelta(seconds=2),
            host_id="quietward-demo-host",
            source="quietward_demo",
            kind=EventKind.PROCESS_START,
            subject="process:synthetic-shell",
            attributes={
                "command_name": "synthetic-shell",
                "suspicious_markers": ["reverse_shell"],
                "external_destination": True,
                "synthetic": True,
            },
            confidence=0.95,
        ),
    ]


def build_demo_result(observed_at: datetime | None = None) -> dict[str, Any]:
    events = build_demo_events(observed_at)
    report = SentinelPipeline().analyze(events).to_dict()
    if report["actions_executed"] != 0:
        raise RuntimeError("QuietWard demo violated the observation-only contract")
    if any(item.get("executable_in_current_mode") for item in report["action_proposals"]):
        raise RuntimeError("QuietWard demo produced an executable proposal")
    return {
        "demo": "quietward-safe-synthetic-demo-v1",
        "events": [event.to_dict() for event in events],
        "analysis": report,
        "safety": {
            "synthetic_data_only": True,
            "host_observation_performed": False,
            "host_state_changed": False,
            "network_request_performed": False,
            "actions_executed": 0,
        },
    }


def _print_human(result: dict[str, Any]) -> None:
    analysis = result["analysis"]
    findings = analysis["findings"]
    print("QuietWard safe demo")
    print("===================")
    print("Synthetic events only. No host scan, network request, or system change is performed.\n")
    print(f"Events analyzed: {analysis['events_analyzed']}")
    print(f"Findings:        {len(findings)}")
    print(f"Actions run:     {analysis['actions_executed']}\n")
    for index, finding in enumerate(findings, start=1):
        print(f"{index}. [{finding['severity'].upper()}] {finding['title']}")
        print(f"   score={finding['score']} evidence={len(finding['evidence_event_ids'])}")
        print(f"   {finding['summary']}")
    print("\nNext: install QuietWard to observe your own machine read-only, or pair findings with QuietWard Response.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a safe synthetic QuietWard demo without observing or modifying the host")
    parser.add_argument("--json", action="store_true", help="print the complete synthetic event and analysis payload as JSON")
    args = parser.parse_args()
    result = build_demo_result()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_human(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
