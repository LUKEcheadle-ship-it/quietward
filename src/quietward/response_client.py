from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import NAMESPACE_URL, uuid5

from .contracts import AnalysisReport, EventKind, SecurityEvent


class ResponseClientError(RuntimeError):
    pass


_CATEGORY_BY_KIND = {
    EventKind.PERSISTENCE_CHANGE: "persistence",
    EventKind.NEW_LISTENING_PORT: "network",
    EventKind.OUTBOUND_CONNECTION: "network",
    EventKind.AUTH_FAILURE: "identity",
    EventKind.PRIVILEGE_ESCALATION: "privilege",
    EventKind.EXECUTABLE_CREATED: "execution",
    EventKind.PROCESS_START: "execution",
    EventKind.FILE_CHANGE: "file",
    EventKind.SENSITIVE_FILE_CHANGE: "file",
    EventKind.SELF_INTEGRITY_CHANGE: "integrity",
    EventKind.EVIDENCE_INTEGRITY_FAILURE: "integrity",
    EventKind.COLLECTOR_HEALTH: "operational",
}


def _derive_hmac_key(secret: str) -> bytes:
    return hashlib.sha256(("quietward-response-v1:" + secret).encode("utf-8")).digest()


def _canonical_request(method: str, target: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), target, timestamp, nonce, body_hash]).encode("utf-8")


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


@dataclass(frozen=True, slots=True)
class ResponseClientConfig:
    base_url: str
    agent_id: str
    key_id: str
    secret: str
    host_id: str
    state_dir: Path
    timeout_seconds: float = 5.0


class QuietWardResponseClient:
    """Optional, failure-contained bridge from QuietWard to QuietWard Response.

    The bridge uses only typed HTTP messages. It never accepts a command string,
    executable path, arbitrary service name, or shell fragment from the server.
    """

    def __init__(self, config: ResponseClientConfig) -> None:
        self.config = config
        self._hmac_key = _derive_hmac_key(config.secret)
        self.outbox_path = config.state_dir / "response-event-outbox.json"
        self.ledger_path = config.state_dir / "response-action-ledger.json"
        self.demo_state_path = config.state_dir / "quietward-response-demo.json"

    @classmethod
    def from_environment(cls, *, host_id: str) -> QuietWardResponseClient | None:
        enabled = os.environ.get("QUIETWARD_RESPONSE_ENABLED", "").strip().lower()
        if enabled not in {"1", "true", "yes", "on"}:
            return None
        required = {
            "base_url": os.environ.get("QUIETWARD_RESPONSE_URL", "").strip(),
            "agent_id": os.environ.get("QUIETWARD_RESPONSE_AGENT_ID", "").strip(),
            "key_id": os.environ.get("QUIETWARD_RESPONSE_KEY_ID", "").strip(),
            "secret": os.environ.get("QUIETWARD_RESPONSE_SECRET", "").strip(),
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ResponseClientError(
                "QuietWard Response is enabled but credentials are incomplete: " + ", ".join(missing)
            )
        state_dir = Path(
            os.environ.get(
                "QUIETWARD_RESPONSE_STATE_DIR",
                str(Path.home() / ".local" / "state" / "quietward"),
            )
        ).expanduser()
        return cls(
            ResponseClientConfig(
                base_url=required["base_url"].rstrip("/"),
                agent_id=required["agent_id"],
                key_id=required["key_id"],
                secret=required["secret"],
                host_id=host_id,
                state_dir=state_dir,
            )
        )

    def _signed_headers(self, method: str, target: str, body: bytes) -> dict[str, str]:
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        signature = hmac.new(
            self._hmac_key,
            _canonical_request(method, target, timestamp, nonce, body),
            hashlib.sha256,
        ).hexdigest()
        return {
            "Content-Type": "application/json",
            "X-QWR-Agent-ID": self.config.agent_id,
            "X-QWR-Key-ID": self.config.key_id,
            "X-QWR-Timestamp": timestamp,
            "X-QWR-Nonce": nonce,
            "X-QWR-Signature": signature,
        }

    def _request(self, method: str, target: str, payload: dict[str, Any] | None = None) -> Any:
        body = b"" if payload is None else json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        request = Request(
            self.config.base_url + target,
            data=body if method.upper() != "GET" else None,
            method=method.upper(),
            headers=self._signed_headers(method, target, body),
        )
        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read()
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:1000]
            raise ResponseClientError(f"response API HTTP {exc.code}: {detail}") from exc
        except (URLError, OSError) as exc:
            raise ResponseClientError(f"response API unavailable: {exc}") from exc
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ResponseClientError("response API returned invalid JSON") from exc

    def _event_payload(self, event: SecurityEvent, report: AnalysisReport) -> dict[str, Any]:
        assessments = {item.event_id: item for item in report.assessments}
        assessment = assessments.get(event.event_id)
        severity = assessment.severity.value if assessment else "medium"
        summary = event.subject
        if assessment and assessment.reasons:
            summary = f"{event.subject}: {assessment.reasons[0]}"
        return {
            "schema_version": "1.0",
            "event_id": str(uuid5(NAMESPACE_URL, f"quietward:{event.event_id}")),
            "source": "quietward",
            "source_version": "0.4.0a2",
            "host_id": event.host_id,
            "host_name": platform.node() or event.host_id,
            "timestamp": event.observed_at.astimezone(timezone.utc).isoformat(),
            "event_type": event.kind.value,
            "category": _CATEGORY_BY_KIND.get(event.kind, "security"),
            "severity": severity,
            "confidence": event.confidence,
            "summary": summary[:2048],
            "evidence": dict(event.attributes),
            "metadata": {
                "operating_system": platform.system() or "unknown",
                "original_quietward_event_id": event.event_id,
                "subject": event.subject,
            },
        }

    def _load_list(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    def _queue_event(self, payload: dict[str, Any]) -> None:
        queued = self._load_list(self.outbox_path)
        event_id = str(payload.get("event_id"))
        if not any(str(item.get("event_id")) == event_id for item in queued):
            queued.append(payload)
        _atomic_json(self.outbox_path, queued[-1000:])

    def flush_outbox(self) -> int:
        queued = self._load_list(self.outbox_path)
        remaining: list[dict[str, Any]] = []
        sent = 0
        for index, payload in enumerate(queued):
            try:
                self._request("POST", "/api/v1/events", payload)
                sent += 1
            except ResponseClientError:
                remaining.extend(queued[index:])
                break
        _atomic_json(self.outbox_path, remaining)
        return sent

    def deliver_cycle(self, events: Iterable[SecurityEvent], report: AnalysisReport) -> dict[str, int]:
        self.flush_outbox()
        sent = 0
        queued = 0
        for event in events:
            if event.host_id != self.config.host_id:
                continue
            payload = self._event_payload(event, report)
            try:
                self._request("POST", "/api/v1/events", payload)
                sent += 1
            except ResponseClientError:
                self._queue_event(payload)
                queued += 1
        return {"sent": sent, "queued": queued}

    def _load_ledger(self) -> dict[str, dict[str, Any]]:
        if not self.ledger_path.exists():
            return {}
        try:
            value = json.loads(self.ledger_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    def _save_ledger(self, value: dict[str, dict[str, Any]]) -> None:
        _atomic_json(self.ledger_path, value)

    def _restart_demo_service(self) -> dict[str, Any]:
        path = self.demo_state_path
        if path.name != "quietward-response-demo.json" or not path.exists():
            raise ResponseClientError("dedicated QuietWard Response demo fixture is not initialized")
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ResponseClientError("demo fixture state is unreadable") from exc
        if state.get("service") != "quietward-response-demo":
            raise ResponseClientError("refusing to modify a non-demo service fixture")
        before = dict(state)
        state["status"] = "running"
        state["restart_count"] = int(state.get("restart_count", 0)) + 1
        state["last_restarted_at"] = datetime.now(timezone.utc).isoformat()
        _atomic_json(path, state)
        return {"before": before, "after": state}

    def initialize_demo_fixture(self, *, unhealthy: bool = True) -> Path:
        state = {
            "service": "quietward-response-demo",
            "status": "unhealthy" if unhealthy else "running",
            "restart_count": 0,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_json(self.demo_state_path, state)
        return self.demo_state_path

    def _execute_action(self, action: dict[str, Any]) -> dict[str, Any]:
        if action.get("target_agent_id") != self.config.agent_id:
            raise ResponseClientError("action targets another agent")
        if action.get("target_host_id") != self.config.host_id:
            raise ResponseClientError("action targets another host")
        if action.get("parameters") not in ({}, None):
            raise ResponseClientError("allowlisted demo action accepts no parameters")
        if action.get("action_type") != "restart_quietward_demo_service":
            raise ResponseClientError("action type is not allowlisted by this QuietWard build")
        return self._restart_demo_service()

    def _post_result(self, action_id: str, status: str, result: dict[str, Any], error: str | None = None) -> Any:
        now = datetime.now(timezone.utc).isoformat()
        payload = {
            "schema_version": "1.0",
            "action_id": action_id,
            "agent_id": self.config.agent_id,
            "host_id": self.config.host_id,
            "status": status,
            "started_at": now,
            "completed_at": now if status in {"succeeded", "failed"} else None,
            "result": result,
            "error": error,
            "evidence": {"executor": "quietward-demo-fixture-v1"},
            "agent_version": "0.4.0a2",
        }
        return self._request("POST", f"/api/v1/actions/{action_id}/result", payload)

    def poll_and_execute(self) -> int:
        actions = self._request(
            "GET", f"/api/v1/agents/{self.config.agent_id}/actions/pending"
        )
        if not isinstance(actions, list):
            raise ResponseClientError("pending action response is not a list")
        ledger = self._load_ledger()
        executed = 0
        for action in actions:
            if not isinstance(action, dict):
                continue
            action_id = str(action.get("action_id") or "")
            if not action_id:
                continue
            prior = ledger.get(action_id)
            if prior and prior.get("status") in {"succeeded", "failed"}:
                self._post_result(
                    action_id,
                    str(prior["status"]),
                    dict(prior.get("result") or {}),
                    prior.get("error"),
                )
                continue
            self._post_result(action_id, "executing", {})
            try:
                result = self._execute_action(action)
                final = {"status": "succeeded", "result": result, "error": None}
            except Exception as exc:  # failure is reported; it must not crash QuietWard service
                final = {"status": "failed", "result": {}, "error": str(exc)[:1000]}
            ledger[action_id] = final
            self._save_ledger(ledger)
            self._post_result(
                action_id,
                str(final["status"]),
                dict(final["result"]),
                final["error"],
            )
            executed += 1
        return executed
