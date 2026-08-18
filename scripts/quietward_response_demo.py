#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socket

from quietward.response_client import QuietWardResponseClient


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manage the dedicated QuietWard Response v1 demo fixture"
    )
    parser.add_argument("command", choices=("init-unhealthy", "status", "sync"))
    parser.add_argument("--host-id", default=socket.gethostname())
    args = parser.parse_args()

    client = QuietWardResponseClient.from_environment(host_id=args.host_id)
    if client is None:
        raise SystemExit(
            "QuietWard Response integration is disabled. Set "
            "QUIETWARD_RESPONSE_ENABLED=true and credentials first."
        )

    if args.command == "init-unhealthy":
        path = client.initialize_demo_fixture(unhealthy=True)
        print(path)
        print(
            json.dumps(
                json.loads(path.read_text(encoding="utf-8")),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "status":
        if not client.demo_state_path.exists():
            print("demo fixture not initialized")
            return 1
        print(client.demo_state_path.read_text(encoding="utf-8"), end="")
        return 0

    # A manual sync is useful for the demo without needing a full collection cycle.
    from quietward.pipeline import SentinelPipeline

    delivery = client.deliver_cycle([], SentinelPipeline().analyze([]))
    executed = client.poll_and_execute()
    print(
        json.dumps(
            {"delivery": delivery, "demo_actions_executed": executed},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
