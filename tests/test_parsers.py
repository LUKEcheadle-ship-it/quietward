from __future__ import annotations

import json
import unittest

from quietward.collectors.parsers import (
    parse_auth_journal,
    parse_docker_ps_output,
    parse_ps_output,
    parse_ss_output,
)


class ParserTests(unittest.TestCase):
    def test_process_arguments_are_hashed_not_persisted(self) -> None:
        secret = "super-secret-token"
        rows = parse_ps_output(f"100 1 root bash /tmp/dropper --token {secret} | bash\n")
        self.assertEqual(len(rows), 1)
        serialized = json.dumps(rows[0].to_dict())
        self.assertNotIn(secret, serialized)
        self.assertIn("volatile_directory_executable", rows[0].suspicious_markers)

    def test_listening_socket_parser(self) -> None:
        rows = parse_ss_output(
            'tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=12,fd=3))\n'
        )
        self.assertEqual(rows[0].port, 2222)
        self.assertTrue(rows[0].external_bind)
        self.assertEqual(rows[0].process_name, "sshd")

    def test_auth_parser_hashes_source_address(self) -> None:
        raw_ip = "203.0.113.42"
        text = json.dumps(
            {
                "MESSAGE": f"Failed password for invalid user admin from {raw_ip}",
                "__REALTIME_TIMESTAMP": "1785430800000000",
            }
        )
        rows = parse_auth_journal(text)
        self.assertEqual(len(rows), 1)
        self.assertNotIn(raw_ip, json.dumps(rows, default=str))
        self.assertEqual(rows[0]["user"], "admin")

    def test_docker_parser_hashes_container_id(self) -> None:
        raw_id = "a" * 64
        rows = parse_docker_ps_output(
            json.dumps(
                {
                    "ID": raw_id,
                    "Image": "jellyfin:latest",
                    "Names": "jellyfin",
                    "Status": "Up",
                }
            )
        )
        self.assertEqual(len(rows), 1)
        self.assertNotEqual(rows[0].container_id_hash, raw_id)


if __name__ == "__main__":
    unittest.main()
