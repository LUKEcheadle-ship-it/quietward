from __future__ import annotations

import json

import httpx

from qw_adversary.live_auth import AgentCredentials, run_stateless_auth_probes
from qw_adversary.models import Verdict


CREDS = AgentCredentials(agent_id="agent-1", key_id="key-1", secret="test-secret", host_id="host-1")


def _code(code: str, status: int = 401) -> httpx.Response:
    return httpx.Response(status, json={"detail": {"code": code}})


def test_stateless_auth_probe_pack_builds_expected_rejection_requests() -> None:
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if "X-QWR-Agent-ID" not in request.headers:
            return _code("missing_agent_auth")
        if request.headers.get("X-QWR-Key-ID") == "wrong-key-id":
            return _code("invalid_key_id")
        timestamp = int(request.headers["X-QWR-Timestamp"])
        if abs(timestamp - 1770000000) > 1000000:  # deterministic branch not used; keep mock simple
            pass
        body = json.loads(request.content)
        if body.get("summary") == "Tampered body":
            return _code("invalid_signature")
        signature_target_probe = body.get("summary") == "Adversarial validation event"
        # The fourth signed request intentionally signs a different query target. We
        # identify it by call order because the wire request itself is correctly query-free.
        if len(seen) == 4 and signature_target_probe:
            return _code("invalid_signature")
        if len(seen) == 5:
            return _code("stale_request")
        if len(seen) == 6:
            return _code("stale_request")
        return _code("unexpected")

    with httpx.Client(transport=httpx.MockTransport(handler), base_url="http://127.0.0.1:8002") as client:
        results = run_stateless_auth_probes(client, CREDS)

    assert len(results) == 6
    assert all(result.verdict == Verdict.PASS for result in results)
    assert all(request.url.host == "127.0.0.1" for request in seen)


def test_stateless_probe_failure_is_reported_not_hidden() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    with httpx.Client(transport=httpx.MockTransport(handler), base_url="http://127.0.0.1:8002") as client:
        results = run_stateless_auth_probes(client, CREDS)

    assert all(result.verdict == Verdict.FAIL for result in results)
