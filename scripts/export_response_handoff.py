#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import platform
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from quietward import __version__
from quietward.config import load_config
from quietward.contracts import SecurityEvent
from quietward.integrations.response import build_response_handoff_events
from quietward.pipeline import SentinelPipeline
from quietward.privacy_identity import PrivacyIdentity


def _load_events(path: Path) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
                if not isinstance(value, dict):
                    raise ValueError("event row must be an object")
                events.append(SecurityEvent.from_dict(value))
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
    return events


def _private_json(path: Path, value: dict[str, Any]) -> None:
    resolved = path.expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    temporary = resolved.with_name(resolved.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short Response handoff write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, resolved)
    try:
        resolved.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a local privacy-preserving QuietWard -> Response handoff file"
    )
    parser.add_argument("event_file", type=Path, help="QuietWard SecurityEvent JSONL input")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("~/.config/quietward/config.json").expanduser(),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    config = load_config(args.config)
    key_path = config.collector.privacy_identity_key_path
    if key_path is None:
        raise ValueError("collector.privacy_identity_key_path is required for Response handoff")
    identity = PrivacyIdentity.load(
        key_path,
        namespace=config.collector.privacy_identity_namespace,
    )
    events = _load_events(args.event_file)
    report = SentinelPipeline().analyze(events)
    payloads = build_response_handoff_events(
        report,
        events,
        privacy_identity=identity,
        source_version=__version__,
        operating_system=platform.system(),
    )
    output = {
        "format": "quietward-response-handoff-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_version": __version__,
        "host_ids": sorted({item["host_id"] for item in payloads}),
        "events": payloads,
        "safety": {
            "observation_only_source": True,
            "actions_executed": 0,
            "executable_authority": False,
            "raw_finding_subjects_included": False,
            "network_request_performed": False,
        },
    }
    if args.output is not None:
        _private_json(args.output, output)
        print(str(args.output.expanduser().resolve()))
    else:
        print(json.dumps(output, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
