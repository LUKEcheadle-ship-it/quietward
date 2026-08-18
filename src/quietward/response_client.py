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


class ResponseHTTPError(ResponseClientError):
    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"response API HTTP {status_code}: {detail}")


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

_OUTBOX_MAX_EVENTS = 1000


def _derive_hmac_key(secret: str) -> bytes:
    return hashlib.sha256(("quietward-response-v1:" + secret).encode("utf-8")).digest()


def _canonical_request(method: str, target: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), target, timestamp, nonce, body_hash]).encode("utf-8")


def _atomic_json(path: Path, value: Any) -> None:
    """Write endpoint integration state atomically with private-file defaults."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short response-state write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


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
            raise ResponseHTTPError(exc.code, detail) from exc
        except (URLError, OSError) as exc:
            raise ResponseClientError(f"response API unavailable: {exc}") from exc
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ResponseClientError("response API returned invalid JSON") from exc

    def _post_event(self, payload: dict[str, Any]) -> None:
        """Submit one event, treating the server's duplicate-ID response as success.

        A timeout can occur after the server commits an event but before the endpoint
        receives the response. Retrying that event must drain the outbox rather than
        leaving it permanently stuck on an expected 409 duplicate response.
        """
        try:
            self._request("POST", "/api/v1/events", payload)
        except ResponseHTTPError as exc:
            if exc.status_code == 409 and "duplicate_event_id" in exc.detail:
                return
            raise

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
        except (OSError, json.JSONDecodeError) as exc:
            raise ResponseClientError("response event outbox is unreadable or invalid") from exc
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise ResponseClientError("response event outbox has an invalid structure")
        return value

    def _queue_event(self, payload: dict[str, Any]) -> None:
        queued = self._load_list(self.outbox_path)
        event_id = str(payload.get("event_id"))
        if any(str(item.get("event_id")) == event_id for item in queued):
            return
        if len(queued) >= _OUTBOX_MAX_EVENTS:
            raise ResponseClientError(
                f"response event outbox capacity reached ({_OUTBOX_MAX_EVENTS}); event was not queued"
            )
        queued.append(payload)
        _atomic_json(self.outbox_path, queued)

    def flush_outbox(self) -> int:
        queued = self._load_list(self.outbox_path)
        remaining: list[dict[str, Any]] = []
        sent = 0
        for index, payload in enumerate(queued):
            try:
                self._post_event(payload)
                sent += 1
            except ResponseClientError:
                remaining.extend(queued[index:])
                break
        _atomic_json(self.outbox_path, remaining)
        return sent

    def _load_demo_state(self) -> dict[str, Any] | None:
        if not self.demo_state_path.exists():
            return None
        try:
            state = json.loads(self.demo_state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ResponseClientError("demo fixture state is unreadable or invalid") from exc
        if not isinstance(state, dict) or state.get("service") != "quietward-response-demo":
            raise ResponseClientError("demo fixture state does not identify the dedicated fixture")
        return state

    def _demo_fixture_event_payload(self, state: dict[str, Any]) -> dict[str, Any] | None:
        if state.get("status") != "unhealthy":
            return None
        restart_count = int(state.get("restart_count", 0))
        generation = f"{state.get('created_at', 'unknown')}:{restart_count}"
        if state.get("last_emitted_generation") == generation:
            return None
        event_id = str(uuid5(NAMESPACE_URL, f"quietward-demo:{self.config.host_id}:{generation}"))
        return {
            "schema_version": "1.0",
            "event_id": event_id,
            "source": "quietward",
            "source_version": "0.4.0a2",
            "host_id": self.config.host_id,
            "host_name": platform.node() or self.config.host_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "quietward_demo_service_unhealthy",
            "category": "operational",
            "severity": "medium",
            "confidence": 1.0,
            "summary": "Dedicated QuietWard Response demo service fixture is unhealthy",
            "evidence": {
                "demo_fixture": True,
                "status": "unhealthy",
                "restart_count": restart_count,
            },
            "metadata": {
                "operating_system": platform.system() or "unknown",
                "demo_only": True,
                "fixture_generation": generation,
            },
        }

    def _deliver_demo_fixture_event(self) -> tuple[int, int]:
        state = self._load_demo_state()
        if state is None:
            return 0, 0
        payload = self._demo_fixture_event_payload(state)
        if payload is None:
            return 0, 0
        generation = str(payload["metadata"]["fixture_generation"])
        try:
            self._post_event(payload)
            sent, queued = 1, 0
        except ResponseClientError:
            self._queue_event(payload)
            sent, queued = 0, 1
        # Mark the generation after either durable queueing or successful delivery.
        # This avoids producing the same event repeatedly while offline.
        state["last_emitted_generation"] = generation
        _atomic_json(self.demo_state_path, state)
        return sent, queued

    def deliver_cycle(self, events: Iterable[SecurityEvent], report: AnalysisReport) -> dict[str, int]:
        sent = self.flush_outbox()
        queued = 0
        for event in events:
            if event.host_id != self.config.host_id:
                continue
            payload = self._event_payload(event, report)
            try:
                self._post_event(payload)
                sent += 1
            except ResponseClientError:
                self._queue_event(payload)
                queued += 1
        demo_sent, demo_queued = self._deliver_demo_fixture_event()
        return {"sent": sent + demo_sent, "queued": queued + demo_queued}

    def _load_ledger(self) -> dict[str, dict[str, Any]]:
        if not self.ledger_path.exists():
            return {}
        try:
            value = json.loads(self.ledger_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ResponseClientError("response action ledger is unreadable or invalid") from exc
        if not isinstance(value, dict) or any(not isinstance(item, dict) for item in value.values()):
            raise ResponseClientError("response action ledger has an invalid structure")
        return value

    def _save_ledger(self, value: dict[str, dict[str, Any]]) -> None:
        _atomic_json(self.ledger_path, value)

    def _restart_demo_service(self, action_id: str) -> dict[str, Any]:
        path = self.demo_state_path
        if path.name != "quietward-response-demo.json" or not path.exists():
            raise ResponseClientError("dedicated QuietWard Response demo fixture is not initialized")
        state = self._load_demo_state()
        if state is None:
            raise ResponseClientError("dedicated QuietWard Response demo fixture is not initialized")
        if state.get("last_action_id") == action_id and isinstance(state.get("last_action_result"), dict):
            return dict(state["last_action_result"])

        before = {key: value for key, value in state.items() if key != "last_action_result"}
        state["status"] = "running"
        state["restart_count"] = int(state.get("restart_count", 0)) + 1
        state["last_restarted_at"] = datetime.now(timezone.utc).isoformat()
        state["last_action_id"] = action_id
        after = {key: value for key, value in state.items() if key != "last_action_result"}
        result = {"before": before, "after": after}
        state["last_action_result"] = result
        _atomic_json(path, state)
        return result

    def initialize_demo_fixture(self, *, unhealthy: bool = True) -> Path:
        state = {
            "service": "quietward-response-demo",
            "status": "unhealthy" if unhealthy else "running",
            "restart_count": 0,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_emitted_generation": None,
            "last_action_id": None,
            "last_action_result": None,
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
        action_id = str(action.get("action_id") or "")
        if not action_id:
            raise ResponseClientError("action id is required")
        return self._restart_demo_service(action_id)

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

            # Persist execution intent before the server transition or local state change.
            # Combined with the demo fixture's action-id marker this closes the crash
            # window that could otherwise cause the same action to be applied twice.
            ledger[action_id] = {"status": "executing", "result": {}, "error": None}
            self._save_ledger(ledger)
            self._post_result(action_id, "executing", {})

            state_before = self._load_demo_state()
            already_applied = bool(state_before and state_before.get("last_action_id") == action_id)
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
            if not already_applied:
                executed += 1
        return executed
