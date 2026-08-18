from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from quietward.contracts import EventKind, SecurityEvent
from quietward.pipeline import SentinelPipeline
from quietward.response_client import (
    QuietWardResponseClient,
    ResponseClientConfig,
    ResponseClientError,
    ResponseHTTPError,
)


def _server_action_payload(action: dict) -> dict:
    """Hydrate compact test overrides into the real Response ActionRead shape."""
    now = datetime.now(timezone.utc)
    payload = {
        "schema_version": "1.0",
        "action_id": "action-test",
        "incident_id": "incident-test",
        "target_agent_id": "agent-test",
        "target_host_id": "host-test",
        "action_type": "restart_quietward_demo_service",
        "parameters": {},
        "requested_at": (now - timedelta(seconds=5)).isoformat(),
        "requested_by": "analyst-test",
        "approval_id": "approval-test",
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "status": "dispatching",
        "policy_allowed": True,
        "policy_reasons": [],
        "dispatched_at": now.isoformat(),
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None,
        "evidence": None,
    }
    payload.update(action)
    return payload


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
            return [_server_action_payload(item) for item in self.pending_actions]
        return {"ok": True}


class DuplicateEventResponseClient(FakeResponseClient):
    def _request(self, method: str, target: str, payload: dict | None = None):
        self.calls.append((method, target, payload))
        if target == "/api/v1/events":
            raise ResponseHTTPError(409, '{"detail":{"code":"duplicate_event_id"}}')
        if target.endswith("/actions/pending"):
            return [_server_action_payload(item) for item in self.pending_actions]
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

    def duplicate_client(self, root: Path) -> DuplicateEventResponseClient:
        return DuplicateEventResponseClient(
            ResponseClientConfig(
                base_url="http://127.0.0.1:8002",
                agent_id="agent-test",
                key_id="key-test",
                secret="secret-test",
                host_id="host-test",
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
            self.assertEqual(
                payload["metadata"]["original_quietward_event_id"],
                "event-local-id",
            )
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
            self.assertEqual(
                queued[0]["metadata"]["original_quietward_event_id"],
                "event-offline",
            )

    def test_duplicate_server_event_is_treated_as_successful_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = self.duplicate_client(root)
            payload = {
                "schema_version": "1.0",
                "event_id": "already-accepted",
                "source": "quietward",
                "host_id": "host-test",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "file_change",
                "severity": "medium",
                "summary": "retry",
            }
            client._queue_event(payload)
            self.assertEqual(client.flush_outbox(), 1)
            self.assertEqual(
                json.loads(client.outbox_path.read_text(encoding="utf-8")),
                [],
            )

    def test_corrupt_outbox_fails_closed_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = self.client(Path(temporary))
            client.outbox_path.write_text("{not-json\n", encoding="utf-8")
            before = client.outbox_path.read_bytes()
            with self.assertRaisesRegex(ResponseClientError, "outbox"):
                client._queue_event({"event_id": "new-event"})
            self.assertEqual(client.outbox_path.read_bytes(), before)

    def test_full_outbox_preserves_existing_events_and_reports_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = self.client(Path(temporary))
            existing = [{"event_id": f"queued-{index}"} for index in range(1000)]
            client.outbox_path.write_text(
                json.dumps(existing),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ResponseClientError, "capacity reached"):
                client._queue_event({"event_id": "overflow"})
            stored = json.loads(client.outbox_path.read_text(encoding="utf-8"))
            self.assertEqual(stored, existing)

    def test_response_state_files_are_private_on_posix(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX file mode semantics do not apply on Windows")
        with tempfile.TemporaryDirectory() as temporary:
            client = self.client(Path(temporary))
            client.initialize_demo_fixture(unhealthy=True)
            client._queue_event({"event_id": "permission-test"})
            client._save_ledger({"action": {"status": "executing"}})
            for path in (
                client.demo_state_path,
                client.outbox_path,
                client.ledger_path,
            ):
                mode = stat.S_IMODE(path.stat().st_mode)
                self.assertEqual(mode, 0o600)

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

    def test_corrupt_demo_fixture_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = self.client(Path(temporary))
            client.demo_state_path.write_text("not-json", encoding="utf-8")
            with self.assertRaisesRegex(ResponseClientError, "demo fixture"):
                client.deliver_cycle([], SentinelPipeline().analyze([]))

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
            self.assertEqual(first_state["last_action_id"], "action-once")
            self.assertEqual(
                unrelated.read_text(encoding="utf-8"),
                '{"status":"do-not-touch"}\n',
            )

            # Server may return the same action again after a transient response failure.
            # The durable local ledger must return the saved result without executing twice.
            self.assertEqual(client.poll_and_execute(), 0)
            second_state = json.loads(fixture.read_text(encoding="utf-8"))
            self.assertEqual(second_state["restart_count"], 1)

    def test_corrupt_action_ledger_fails_closed_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = self.client(root)
            fixture = client.initialize_demo_fixture(unhealthy=True)
            client.ledger_path.write_text("{broken", encoding="utf-8")
            client.pending_actions = [
                {
                    "schema_version": "1.0",
                    "action_id": "action-ledger-corrupt",
                    "incident_id": "incident-test",
                    "target_agent_id": "agent-test",
                    "target_host_id": "host-test",
                    "action_type": "restart_quietward_demo_service",
                    "parameters": {},
                    "status": "dispatching",
                }
            ]
            with self.assertRaisesRegex(ResponseClientError, "ledger"):
                client.poll_and_execute()
            state = json.loads(fixture.read_text(encoding="utf-8"))
            self.assertEqual(state["status"], "unhealthy")
            self.assertEqual(state["restart_count"], 0)

    def test_crash_recovery_does_not_reapply_action_after_fixture_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = self.client(root)
            fixture = client.initialize_demo_fixture(unhealthy=True)
            action = {
                "schema_version": "1.0",
                "action_id": "action-crash-window",
                "incident_id": "incident-test",
                "target_agent_id": "agent-test",
                "target_host_id": "host-test",
                "action_type": "restart_quietward_demo_service",
                "parameters": {},
                "status": "executing",
            }

            # Simulate the process dying after the fixture write but before the
            # terminal ledger/result was persisted to Response.
            first_result = client._execute_action(action)
            client._save_ledger(
                {
                    "action-crash-window": {
                        "status": "executing",
                        "result": {},
                        "error": None,
                    }
                }
            )
            client.pending_actions = [action]

            self.assertEqual(client.poll_and_execute(), 0)
            state = json.loads(fixture.read_text(encoding="utf-8"))
            self.assertEqual(state["restart_count"], 1)
            ledger = client._load_ledger()
            self.assertEqual(ledger["action-crash-window"]["status"], "succeeded")
            self.assertEqual(ledger["action-crash-window"]["result"], first_result)


if __name__ == "__main__":
    unittest.main()
