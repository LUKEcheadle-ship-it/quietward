from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

import httpx

from .matrix import CASES
from .models import AttackCase, CaseResult, Verdict
from .signing import sign_request

AUTH_HEADERS = {
    "agent_id": "X-QWR-Agent-ID",
    "timestamp": "X-QWR-Timestamp",
    "nonce": "X-QWR-Nonce",
    "signature": "X-QWR-Signature",
    "key_id": "X-QWR-Key-ID",
}


@dataclass(frozen=True, slots=True)
class AgentCredentials:
    agent_id: str
    key_id: str
    secret: str
    host_id: str


@dataclass(frozen=True, slots=True)
class ProbeExpectation:
    status_code: int
    detail_code: str | None


def _case(case_id: str) -> AttackCase:
    return next(item for item in CASES if item.case_id == case_id)


def _event(*, host_id: str, event_id: str | None = None, summary: str = "Adversarial validation event") -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "event_id": event_id or str(uuid4()),
        "source": "quietward",
        "source_version": "adversarial-validation/0.1",
        "host_id": host_id,
        "host_name": f"{host_id}.validation.local",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "adversarial_validation_probe",
        "category": "validation",
        "severity": "info",
        "confidence": 1.0,
        "summary": summary,
        "evidence": {"synthetic": True, "test_owned": True},
        "metadata": {"adversarial_validation": True},
    }


def _json_bytes(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _headers(
    credentials: AgentCredentials,
    *,
    method: str,
    target_to_sign: str,
    body_to_sign: bytes,
    timestamp: str | None = None,
    nonce: str | None = None,
    key_id: str | None = None,
) -> dict[str, str]:
    timestamp = timestamp or str(int(time.time()))
    nonce = nonce or secrets.token_hex(16)
    return {
        "Content-Type": "application/json",
        AUTH_HEADERS["agent_id"]: credentials.agent_id,
        AUTH_HEADERS["timestamp"]: timestamp,
        AUTH_HEADERS["nonce"]: nonce,
        AUTH_HEADERS["signature"]: sign_request(
            credentials.secret,
            method=method,
            target=target_to_sign,
            timestamp=timestamp,
            nonce=nonce,
            body=body_to_sign,
        ),
        AUTH_HEADERS["key_id"]: key_id or credentials.key_id,
    }


def _detail_code(response: httpx.Response) -> str | None:
    try:
        payload = response.json()
    except ValueError:
        return None
    detail = payload.get("detail") if isinstance(payload, dict) else None
    if isinstance(detail, dict):
        code = detail.get("code")
        return str(code) if code is not None else None
    return None


def _result(case_id: str, response: httpx.Response, expected: ProbeExpectation) -> CaseResult:
    actual_code = _detail_code(response)
    passed = response.status_code == expected.status_code and (
        expected.detail_code is None or actual_code == expected.detail_code
    )
    return CaseResult(
        case=_case(case_id),
        verdict=Verdict.PASS if passed else Verdict.FAIL,
        evidence={
            "status_code": response.status_code,
            "detail_code": actual_code,
            "expected_status": expected.status_code,
            "expected_detail_code": expected.detail_code,
        },
        detail="boundary behaved as expected" if passed else "unexpected HTTP response",
    )


def run_stateless_auth_probes(client: httpx.Client, credentials: AgentCredentials) -> list[CaseResult]:
    """Run safe auth rejection probes that do not create accepted events."""
    target = "/api/v1/events"
    results: list[CaseResult] = []

    body = _json_bytes(_event(host_id=credentials.host_id))
    response = client.post(target, content=body, headers={"Content-Type": "application/json"})
    results.append(_result("AUTH-001", response, ProbeExpectation(401, "missing_agent_auth")))

    body = _json_bytes(_event(host_id=credentials.host_id))
    headers = _headers(credentials, method="POST", target_to_sign=target, body_to_sign=body, key_id="wrong-key-id")
    response = client.post(target, content=body, headers=headers)
    results.append(_result("AUTH-002", response, ProbeExpectation(401, "invalid_key_id")))

    original = _json_bytes(_event(host_id=credentials.host_id, summary="Signed original body"))
    tampered = _json_bytes(_event(host_id=credentials.host_id, summary="Tampered body"))
    headers = _headers(credentials, method="POST", target_to_sign=target, body_to_sign=original)
    response = client.post(target, content=tampered, headers=headers)
    results.append(_result("AUTH-003", response, ProbeExpectation(401, "invalid_signature")))

    body = _json_bytes(_event(host_id=credentials.host_id))
    headers = _headers(credentials, method="POST", target_to_sign=f"{target}?tampered=1", body_to_sign=body)
    response = client.post(target, content=body, headers=headers)
    results.append(_result("AUTH-004", response, ProbeExpectation(401, "invalid_signature")))

    body = _json_bytes(_event(host_id=credentials.host_id))
    stale = str(int(time.time()) - 86400)
    headers = _headers(credentials, method="POST", target_to_sign=target, body_to_sign=body, timestamp=stale)
    response = client.post(target, content=body, headers=headers)
    results.append(_result("AUTH-005", response, ProbeExpectation(401, "stale_request")))

    body = _json_bytes(_event(host_id=credentials.host_id))
    future = str(int(time.time()) + 86400)
    headers = _headers(credentials, method="POST", target_to_sign=target, body_to_sign=body, timestamp=future)
    response = client.post(target, content=body, headers=headers)
    results.append(_result("AUTH-006", response, ProbeExpectation(401, "stale_request")))

    return results


def run_stateful_auth_probes(client: httpx.Client, credentials: AgentCredentials) -> list[CaseResult]:
    """Create test-owned synthetic events to prove replay and UUID-conflict behavior."""
    target = "/api/v1/events"
    results: list[CaseResult] = []

    event_id = str(uuid4())
    body = _json_bytes(_event(host_id=credentials.host_id, event_id=event_id, summary="Replay baseline"))
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    headers = _headers(
        credentials,
        method="POST",
        target_to_sign=target,
        body_to_sign=body,
        timestamp=timestamp,
        nonce=nonce,
    )
    first = client.post(target, content=body, headers=headers)
    second = client.post(target, content=body, headers=headers)
    if first.status_code != 201:
        results.append(CaseResult(
            case=_case("AUTH-007"),
            verdict=Verdict.FAIL,
            evidence={"first_status": first.status_code, "first_detail": _detail_code(first)},
            detail="baseline request was not accepted, so replay could not be proven",
        ))
    else:
        results.append(_result("AUTH-007", second, ProbeExpectation(401, "replayed_nonce")))

    conflict_event_id = str(uuid4())
    first_body = _json_bytes(_event(host_id=credentials.host_id, event_id=conflict_event_id, summary="UUID baseline"))
    first_headers = _headers(credentials, method="POST", target_to_sign=target, body_to_sign=first_body)
    accepted = client.post(target, content=first_body, headers=first_headers)
    changed_body = _json_bytes(_event(host_id=credentials.host_id, event_id=conflict_event_id, summary="UUID changed content"))
    changed_headers = _headers(credentials, method="POST", target_to_sign=target, body_to_sign=changed_body)
    changed = client.post(target, content=changed_body, headers=changed_headers)
    if accepted.status_code != 201:
        results.append(CaseResult(
            case=_case("AUTH-008"),
            verdict=Verdict.FAIL,
            evidence={"first_status": accepted.status_code, "first_detail": _detail_code(accepted)},
            detail="baseline event was not accepted, so UUID conflict could not be proven",
        ))
    else:
        results.append(_result("AUTH-008", changed, ProbeExpectation(409, "event_id_conflict")))

    return results
