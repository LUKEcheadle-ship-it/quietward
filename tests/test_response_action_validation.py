from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quietward.response_client import (
    QuietWardResponseClient,
    ResponseClientConfig,
    ResponseClientError,
)


class FakeActionClient(QuietWardResponseClient):
    def __init__(self, root: Path) -> None:
        super().__init__(
            ResponseClientConfig(
                base_url="http://127.0.0.1:8002",
                agent_id="agent-test",
                key_id="key-test",
                secret="secret-test",
                host_id="host-test",
                state_dir=root,
            )
        )
        self.pending_actions: list[dict] = []
        self.result_posts: list[dict] = []

    def _request(self, method: str, target: str, payload: dict | None = None):
        if target.endswith("/actions/pending"):
            return list(self.pending_actions)
        if target.endswith("/result"):
            assert payload is not None
            self.result_posts.append(dict(payload))
            return {"ok": True}
        return {"ok": True}


def action_payload(*, status: str = "dispatching", expires_delta: int = 300) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "1.0",
        "action_id": "action-validation-test",
        "incident_id": "incident-validation-test",
        "target_agent_id": "agent-test",
        "target_host_id": "host-test",
        "action_type": "restart_quietward_demo_service",
        "parameters": {},
        "requested_at": (now - timedelta(seconds=10)).isoformat(),
        "requested_by": "analyst-test",
        "approval_id": "approval-validation-test",
        "expires_at": (now + timedelta(seconds=expires_delta)).isoformat(),
        "status": status,
        "policy_allowed": True,
        "policy_reasons": [],
        "dispatched_at": now.isoformat(),
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None,
        "evidence": None,
    }


class ResponseActionValidationTests(unittest.TestCase):
    def test_expired_new_dispatch_is_refused_before_fixture_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = FakeActionClient(Path(temporary))
            fixture = client.initialize_demo_fixture(unhealthy=True)
            client.pending_actions = [action_payload(expires_delta=-1)]

            with self.assertRaisesRegex(ResponseClientError, "expired"):
                client.poll_and_execute()

            state = json.loads(fixture.read_text(encoding="utf-8"))
            self.assertEqual(state["status"], "unhealthy")
            self.assertEqual(state["restart_count"], 0)
            self.assertEqual(client.result_posts, [])

    def test_server_only_executing_state_is_refused_without_local_intent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = FakeActionClient(Path(temporary))
            fixture = client.initialize_demo_fixture(unhealthy=True)
            client.pending_actions = [action_payload(status="executing")]

            with self.assertRaisesRegex(ResponseClientError, "without matching local execution intent"):
                client.poll_and_execute()

            state = json.loads(fixture.read_text(encoding="utf-8"))
            self.assertEqual(state["restart_count"], 0)

    def test_executing_recovery_with_persisted_intent_can_complete_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = FakeActionClient(Path(temporary))
            fixture = client.initialize_demo_fixture(unhealthy=True)
            action = action_payload(status="executing")
            client._save_ledger(
                {
                    action["action_id"]: {
                        "status": "executing",
                        "result": {},
                        "error": None,
                    }
                }
            )
            client.pending_actions = [action]

            self.assertEqual(client.poll_and_execute(), 1)
            state = json.loads(fixture.read_text(encoding="utf-8"))
            self.assertEqual(state["status"], "running")
            self.assertEqual(state["restart_count"], 1)
            self.assertEqual(client._load_ledger()[action["action_id"]]["status"], "succeeded")

    def test_fixture_marker_recovers_when_terminal_ledger_write_was_lost(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = FakeActionClient(Path(temporary))
            fixture = client.initialize_demo_fixture(unhealthy=True)
            action = action_payload(status="executing")
            first_result = client._execute_action(action)
            client.pending_actions = [action]

            self.assertEqual(client.poll_and_execute(), 0)
            state = json.loads(fixture.read_text(encoding="utf-8"))
            self.assertEqual(state["restart_count"], 1)
            ledger = client._load_ledger()[action["action_id"]]
            self.assertEqual(ledger["status"], "succeeded")
            self.assertEqual(ledger["result"], first_result)

    def test_unexpected_fields_or_unapproved_policy_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = FakeActionClient(Path(temporary))
            client.initialize_demo_fixture(unhealthy=True)

            injected = action_payload()
            injected["command"] = "not-allowed"
            client.pending_actions = [injected]
            with self.assertRaisesRegex(ResponseClientError, "unsupported fields"):
                client.poll_and_execute()

            blocked = action_payload()
            blocked["policy_allowed"] = False
            client.pending_actions = [blocked]
            with self.assertRaisesRegex(ResponseClientError, "not policy-allowed"):
                client.poll_and_execute()


if __name__ == "__main__":
    unittest.main()
