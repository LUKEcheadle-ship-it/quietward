from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from quietward.response_client import QuietWardResponseClient, ResponseClientError


_REQUIRED_ENV = {
    "QUIETWARD_RESPONSE_ENABLED": "true",
    "QUIETWARD_RESPONSE_URL": "http://127.0.0.1:8002",
    "QUIETWARD_RESPONSE_AGENT_ID": "agent-test",
    "QUIETWARD_RESPONSE_KEY_ID": "key-test",
    "QUIETWARD_RESPONSE_SECRET": "secret-test",
}


class ResponseStateDirectoryTests(unittest.TestCase):
    def test_configured_quietward_state_dir_is_default_for_response_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary) / "quietward-state"
            with patch.dict(os.environ, _REQUIRED_ENV, clear=True):
                client = QuietWardResponseClient.from_environment(
                    host_id="host-test",
                    default_state_dir=state_dir,
                )
            self.assertIsNotNone(client)
            assert client is not None
            self.assertEqual(client.config.state_dir, state_dir)
            self.assertEqual(client.demo_state_path.parent, state_dir)

    def test_explicit_response_state_override_wins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            default_dir = root / "quietward-state"
            override_dir = root / "response-state"
            values = {
                **_REQUIRED_ENV,
                "QUIETWARD_RESPONSE_STATE_DIR": str(override_dir),
            }
            with patch.dict(os.environ, values, clear=True):
                client = QuietWardResponseClient.from_environment(
                    host_id="host-test",
                    default_state_dir=default_dir,
                )
            self.assertIsNotNone(client)
            assert client is not None
            self.assertEqual(client.config.state_dir, override_dir)

    def test_relative_response_state_override_fails_closed(self) -> None:
        values = {
            **_REQUIRED_ENV,
            "QUIETWARD_RESPONSE_STATE_DIR": "relative-state",
        }
        with patch.dict(os.environ, values, clear=True):
            with self.assertRaisesRegex(ResponseClientError, "must be absolute"):
                QuietWardResponseClient.from_environment(
                    host_id="host-test",
                    default_state_dir=Path.home(),
                )


if __name__ == "__main__":
    unittest.main()
