from __future__ import annotations

import http.client
from email.message import Message
from unittest.mock import Mock
import tempfile
import unittest
from pathlib import Path

from quietward.config import DashboardSettings, StorageSettings
from quietward.dashboard import DashboardServer
from quietward.enhanced_dashboard import QuietWardDashboardServer


class DashboardAuthorityTests(unittest.TestCase):
    def test_authority_is_checked_before_base_and_enhanced_routes(self):
        for server_type in (DashboardServer, QuietWardDashboardServer):
            with self.subTest(server=server_type.__name__), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                server = server_type(DashboardSettings(bind="127.0.0.1", port=0),
                                     StorageSettings(root / "db", root / "alerts"))
                server.start()
                try:
                    port = server.address[1]
                    for path in ("/", "/health", "/api/summary", "/api/incidents"):
                        for hosts in ([], ["example.invalid"], [f"example.invalid:{port}"],
                                      ["127.0.0.1:1"], [f"localhost:{port}", f"localhost:{port}"],
                                      [f"localhost:{port}@example.invalid"],
                                      [f"localhost:{port},example.invalid"]):
                            with self.subTest(path=path, hosts=hosts):
                                conn = http.client.HTTPConnection(*server.address, timeout=2)
                                conn.putrequest("GET", path, skip_host=True)
                                for host in hosts:
                                    conn.putheader("Host", host)
                                conn.endheaders()
                                response = conn.getresponse()
                                self.assertEqual(response.status, 400)
                                response.read()
                                conn.close()
                    self.assertFalse((root / "db").exists())
                    for host in (f"127.0.0.1:{port}", f"localhost:{port}", f"LOCALHOST:{port}"):
                        conn = http.client.HTTPConnection(*server.address, timeout=2)
                        conn.request("GET", "/health", headers={"Host": host})
                        response = conn.getresponse()
                        self.assertEqual(response.status, 200)
                        response.read()
                        conn.close()
                    conn = http.client.HTTPConnection(*server.address, timeout=2)
                    conn.request("POST", "/", headers={"Host": "example.invalid"})
                    response = conn.getresponse()
                    self.assertEqual(response.status, 400)
                    response.read()
                    conn.close()
                finally:
                    server.close()

    def test_wildcard_bind_rejected_even_with_private_bind_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for address in ("0.0.0.0", "::"):
                with self.subTest(address=address), self.assertRaisesRegex(ValueError, "private-network"):
                    DashboardServer(DashboardSettings(bind=address, port=0,
                                    allow_private_network_bind=True, token_file=root / "unused-token"),
                                    StorageSettings(root / "db", root / "alerts"))

    def test_private_listener_and_standard_port_authorities(self):
        server = object.__new__(DashboardServer)
        server.settings = DashboardSettings(bind="192.168.1.10", port=80)
        server.httpd = Mock(server_address=("192.168.1.10", 80))
        for host, expected in (("192.168.1.10", True), ("192.168.1.10:80", True),
                               ("localhost:80", False), ("192.168.1.11:80", False),
                               ("192.168.1.10:8080", False)):
            headers = Message()
            headers["Host"] = host
            self.assertEqual(server._valid_host(Mock(headers=headers)), expected)

    def test_token_auth_rejects_missing_duplicate_and_non_ascii_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            token = "synthetic-test-token-not-a-secret"
            token_file = root / "token"
            token_file.write_text(token)
            token_file.chmod(0o600)
            server = DashboardServer(DashboardSettings(bind="127.0.0.1", port=0,
                                     token_file=token_file), StorageSettings(root / "db", root / "alerts"))
            server.start()
            try:
                for values, status in (([], 401), (["Bearer wrong"], 401),
                                       (["Bearer é"], 401),
                                       ([f"Bearer {token}", f"Bearer {token}"], 401),
                                       ([f"Bearer {token}"], 200)):
                    with self.subTest(values=values):
                        conn = http.client.HTTPConnection(*server.address, timeout=2)
                        conn.putrequest("GET", "/health")
                        for value in values:
                            conn.putheader("Authorization", value)
                        conn.endheaders()
                        response = conn.getresponse()
                        self.assertEqual(response.status, status)
                        response.read()
                        conn.close()
            finally:
                server.close()
