from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from quietward.contracts import EventKind, SecurityEvent
from quietward.pipeline import SentinelPipeline
from quietward.response_client import (
    QuietWardResponseClient,
    ResponseClientConfig,
    ResponseClientError,
)


class FakeResponseClient(QuietWardResponseClient):
    def __init__(self, config: ResponseClientConfig) -> None:
        super().__init__(config)
        self.calls: list[tuple[str, str, dict | None]] = []
        self.fail_events = False
        self.pending_actions: list[dict] = []

    def _request(self, method: str, target: str, payload: dict | None = None):
        self.calls.append((method, target, payload))
        if target == "/api/v1/events" and self.fail_events:
            raise ResponseClientError("offline")
        if target.endswith("/actions/pending"):
            return list(self.pending_actions)
        return {"ok": True}


class ResponseClientTests(unittest.TestCase):
    def client(self, root: Path, host_id: str = "host-test") -> FakeResponseClient:
        return FakeResponseClient(
            ResponseClientConfig(
                base_url="http://127.0.0.1:8002",
                agent_id="agent-test",
                key_id="key-test",
                secret="secret-test",
                host_id=host_id,
                state_dir=root,
            )
        )

    def test_integration_is_disabled_by_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(QuietWardResponseClient.from_environment(host_id="host-test"))

    def test_event_is_normalized_for_response_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = self.client(Path(temporary))
            event = SecurityEvent(
                "event-local-id",
                datetime.now(timezone.utc),
                "host-test",
                "collector",
                EventKind.PROCESS_START,
                "process:test",
                {"pid": 1234},
                0.8,
            )
            report = SentinelPipeline().analyze([event])
            result = client.deliver_cycle([event], report)
            self.assertEqual(result, {"sent": 1, "queued": 0})
            method, target, payload = client.calls[0]
            self.assertEqual((method, target), ("POST", "/api/v1/events"))
            self.assertIsNotNone(payload)
            assert payload is not None
            self.assertEqual(payload["source"], "quietward")
            self.assertEqual(payload["host_id"], "host-test")
            self.assertEqual(payload["event_type"], "process_start")
            self.assertEqual(payload["metadata"]["original_quietward_event_id"], "event-local-id")
            # Response requires UUID event IDs even though QuietWard local IDs may use another format.
            self.assertNotEqual(payload["event_id"], "event-local-id")

    def test_response_outage_queues_event_without_losing_local_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = self.client(Path(temporary))
            client.fail_events = True
            event = SecurityEvent(
                "event-offline",
                datetime.now(timezone.utc),
                "host-test",
                "collector",
                EventKind.FILE_CHANGE,
                "/tmp/test",
            )
            report = SentinelPipeline().analyze([event])
            result = client.deliver_cycle([event], report)
            self.assertEqual(result["queued"], 1)
            queued = json.loads(client.outbox_path.read_text(encoding="utf-8"))
            self.assertEqual(len(queued), 1)
            self.assertEqual(queued[0]["metadata"]["original_quietward_event_id"], "event-offline")

    def test_unhealthy_demo_fixture_emits_exactly_one_generation_event(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = self.client(Path(temporary))
            client.initialize_demo_fixture(unhealthy=True)
            empty_report = SentinelPipeline().analyze([])
            first = client.deliver_cycle([], empty_report)
            second = client.deliver_cycle([], empty_report)
            self.assertEqual(first, {"sent": 1, "queued": 0})
            self.assertEqual(second, {"sent": 0, "queued": 0})
            event_calls = [item for item in client.calls if item[1] == "/api/v1/events"]
            self.assertEqual(len(event_calls), 1)
            payload = event_calls[0][2]
            assert payload is not None
            self.assertEqual(payload["event_type"], "quietward_demo_service_unhealthy")
            self.assertTrue(payload["metadata"]["demo_only"])

    def test_demo_action_accepts_no_arbitrary_target_or_parameters(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = self.client(Path(temporary))
            client.initialize_demo_fixture(unhealthy=True)
            base = {
                "action_id": "action-test",
                "target_agent_id": "agent-test",
                "target_host_id": "host-test",
                "action_type": "restart_quietward_demo_service",
                "parameters": {},
            }
            invalid_type = dict(base, action_type="run_shell")
            with self.assertRaisesRegex(ResponseClientError, "not allowlisted"):
                client._execute_action(invalid_type)
            invalid_parameters = dict(base, parameters={"service": "ssh"})
            with self.assertRaisesRegex(ResponseClientError, "no parameters"):
                client._execute_action(invalid_parameters)
            wrong_host = dict(base, target_host_id="another-host")
            with self.assertRaisesRegex(ResponseClientError, "another host"):
                client._execute_action(wrong_host)

    def test_demo_action_only_changes_dedicated_fixture_and_is_not_reexecuted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = self.client(root)
            fixture = client.initialize_demo_fixture(unhealthy=True)
            unrelated = root / "unrelated.json"
            unrelated.write_text('{"status":"do-not-touch"}\n', encoding="utf-8")
            action = {
                "schema_version": "1.0",
                "action_id": "action-once",
                "incident_id": "incident-test",
                "target_agent_id": "agent-test",
                "target_host_id": "host-test",
                "action_type": "restart_quietward_demo_service",
                "parameters": {},
                "status": "dispatching",
            }
            client.pending_actions = [action]
            self.assertEqual(client.poll_and_execute(), 1)
            first_state = json.loads(fixture.read_text(encoding="utf-8"))
            self.assertEqual(first_state["status"], "running")
            self.assertEqual(first_state["restart_count"], 1)
            self.assertEqual(unrelated.read_text(encoding="utf-8"), '{"status":"do-not-touch"}\n')

            # Server may return dispatching again after a transient response failure.
            # The durable local ledger must return the saved result without executing twice.
            self.assertEqual(client.poll_and_execute(), 0)
            second_state = json.loads(fixture.read_text(encoding="utf-8"))
            self.assertEqual(second_state["restart_count"], 1)


if __name__ == "__main__":
    unittest.main()
