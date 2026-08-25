from __future__ import annotations

import json
import unittest

from quietward.collectors.command import (
    DOCKER_INSPECT_PREFIX,
    DOCKER_PS_COMMAND,
    CommandResult,
    ReadOnlyCommandRunner,
)
from quietward.collectors.debian import (
    DebianCollectorConfig,
    DebianReadOnlyCollector,
)
from quietward.collectors.docker_batch import parse_docker_inspect_batch_output
from quietward.collectors.models import ContainerRecord


class FakeRunner:
    def __init__(self, outputs) -> None:
        self.outputs = outputs
        self.calls = []

    def run(self, argv):
        command = tuple(argv)
        self.calls.append(command)
        value = self.outputs.get(command)
        if value is None:
            return CommandResult(command, 127, "", "not configured")
        return CommandResult(command, 0, value, "")


def inspect_object(*, privileged: bool, restart_count: int = 0) -> dict:
    return {
        "HostConfig": {
            "Privileged": privileged,
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "",
            "ReadonlyRootfs": False,
            "SecurityOpt": ["no-new-privileges:true"],
            "CapAdd": [],
        },
        "State": {"Status": "running"},
        "Config": {"Image": "example:v1"},
        "Mounts": [],
        "RestartCount": restart_count,
    }


class DockerBatchPerformanceTests(unittest.TestCase):
    def test_allowlist_accepts_only_bounded_container_id_batch(self) -> None:
        ids = tuple(f"{index:012x}" for index in range(1, 4))
        command = (*DOCKER_INSPECT_PREFIX, *ids)
        self.assertEqual(ReadOnlyCommandRunner.validate(command), command)

        too_many = tuple(f"{index:012x}" for index in range(1, 52))
        with self.assertRaisesRegex(ValueError, "allowlist"):
            ReadOnlyCommandRunner.validate((*DOCKER_INSPECT_PREFIX, *too_many))
        with self.assertRaisesRegex(ValueError, "allowlist"):
            ReadOnlyCommandRunner.validate(
                (*DOCKER_INSPECT_PREFIX, "not-a-container-id")
            )

    def test_batch_parser_preserves_order_and_security_context(self) -> None:
        bases = (
            ContainerRecord("hash-a", "example:v1", "a", "Up"),
            ContainerRecord("hash-b", "example:v1", "b", "Up"),
        )
        text = "\n".join(
            (
                json.dumps(inspect_object(privileged=True)),
                json.dumps(inspect_object(privileged=False, restart_count=6)),
            )
        )
        parsed = parse_docker_inspect_batch_output(text, bases)
        self.assertEqual(len(parsed), 2)
        self.assertTrue(parsed[0].privileged)
        self.assertIn("privileged_container", parsed[0].security_markers)
        self.assertEqual(parsed[1].restart_count, 6)
        self.assertIn("restart_loop", parsed[1].security_markers)

    def test_linux_collector_uses_one_inspect_for_multiple_containers(self) -> None:
        ids = ("aaaaaaaaaaaa", "bbbbbbbbbbbb")
        ps_output = "\n".join(
            (
                json.dumps(
                    {
                        "ID": ids[0],
                        "Image": "example:v1",
                        "Names": "one",
                        "Status": "Up",
                    }
                ),
                json.dumps(
                    {
                        "ID": ids[1],
                        "Image": "example:v1",
                        "Names": "two",
                        "Status": "Up",
                    }
                ),
            )
        )
        batch_command = (*DOCKER_INSPECT_PREFIX, *ids)
        inspect_output = "\n".join(
            (
                json.dumps(inspect_object(privileged=False)),
                json.dumps(inspect_object(privileged=True)),
            )
        )
        runner = FakeRunner(
            {
                DOCKER_PS_COMMAND: ps_output,
                batch_command: inspect_output,
            }
        )
        collector = DebianReadOnlyCollector(
            DebianCollectorConfig(
                sensitive_files=(),
                include_processes=False,
                include_sockets=False,
                include_connections=False,
                include_auth_journal=False,
                include_docker=True,
                include_persistence=False,
            ),
            runner=runner,
            host_id="host-a",
        )
        result = collector.collect(None)
        self.assertEqual(len(result.snapshot.containers), 2)
        self.assertEqual(runner.calls, [DOCKER_PS_COMMAND, batch_command])
        self.assertFalse(result.snapshot.containers[0].privileged)
        self.assertTrue(result.snapshot.containers[1].privileged)


if __name__ == "__main__":
    unittest.main()
