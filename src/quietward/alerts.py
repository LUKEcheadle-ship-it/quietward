from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Protocol

from .storage import SentinelStore


class Explainer(Protocol):
    def explain(self, finding: dict[str, Any]) -> dict[str, Any]: ...


class DeterministicExplainer:
    def explain(self, finding: dict[str, Any]) -> dict[str, Any]:
        evidence_count = len(finding.get("evidence_event_ids") or [])
        return {
            "explanation": (
                f"QuietWard correlated {evidence_count} normalized security event(s) for "
                f"{finding.get('subject', 'an unknown subject')} at "
                f"{finding.get('severity', 'unknown')} severity. "
                "The underlying scanner and collector evidence remains authoritative."
            ),
            "recommended_next_steps": [
                "Review the normalized evidence and collector provenance.",
                "Confirm whether the activity was expected before approving any containment.",
            ],
            "uncertainty": "This deterministic explanation does not add evidence and cannot confirm intent.",
            "action_authorized": False,
            "source": "deterministic_fallback",
        }


class LocalAlertSink:
    """Appends high-severity normalized alerts to a private local JSONL file."""

    def __init__(
        self,
        path: Path,
        explainer: Explainer | None = None,
        max_line_bytes: int = 64_000,
    ) -> None:
        self.path = path
        self.explainer = explainer or DeterministicExplainer()
        self.max_line_bytes = max_line_bytes
        if max_line_bytes <= 0:
            raise ValueError("max_line_bytes must be positive")

    def emit_pending(self, store: SentinelStore, limit: int = 100) -> int:
        emitted = 0
        for finding in store.pending_alert_findings(limit=limit):
            payload = {
                "alert_version": "quietward-alert-v1",
                "finding": finding,
                "explanation": self.explainer.explain(finding),
                "actions_executed": 0,
            }
            self._append(payload)
            store.mark_alerted(finding)
            emitted += 1
        return emitted

    def _append(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        if len(serialized) > self.max_line_bytes:
            raise ValueError("alert payload exceeds maximum line size")
        descriptor = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        try:
            os.write(descriptor, serialized + b"\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass
