from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Protocol

from .operational_findings import pending_incident_alert_findings
from .storage import SentinelStore


class Explainer(Protocol):
    def explain(self, finding: dict[str, Any]) -> dict[str, Any]: ...


class DeterministicExplainer:
    def explain(self, finding: dict[str, Any]) -> dict[str, Any]:
        evidence_count = len(finding.get("evidence_event_ids") or [])
        return {
            "explanation": (
                f"QuietWard correlated {evidence_count} normalized security event(s) for "
                f"{finding.get('subject', 'an unknown subject')} at {finding.get('severity', 'unknown')} severity. "
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
    """Appends high-severity normalized alerts to a bounded private JSONL file."""

    def __init__(
        self,
        path: Path,
        explainer: Explainer | None = None,
        max_line_bytes: int = 64_000,
        max_file_bytes: int = 10_000_000,
    ) -> None:
        self.path = path
        self.explainer = explainer or DeterministicExplainer()
        self.max_line_bytes = max_line_bytes
        self.max_file_bytes = max_file_bytes
        if max_line_bytes <= 0:
            raise ValueError("max_line_bytes must be positive")
        if max_file_bytes <= max_line_bytes:
            raise ValueError("max_file_bytes must exceed max_line_bytes")

    def emit_pending(self, store: SentinelStore, limit: int = 100) -> int:
        emitted = 0
        for finding in pending_incident_alert_findings(store, limit=limit):
            payload = {
                "alert_version": "quietward-alert-v2",
                "finding": finding,
                "explanation": self.explainer.explain(finding),
                "actions_executed": 0,
            }
            self._append(payload)
            store.mark_alerted(finding)
            emitted += 1
        return emitted

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("alert-log write made no progress")
            offset += written

    def _reject_symlink(self, path: Path) -> None:
        if path.is_symlink():
            raise ValueError(f"alert log path may not be a symlink: {path}")

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        self._reject_symlink(self.path)
        if not self.path.exists():
            return
        if self.path.stat().st_size + incoming_bytes <= self.max_file_bytes:
            return
        backup = self.path.with_name(self.path.name + ".1")
        self._reject_symlink(backup)
        if backup.exists():
            if not backup.is_file():
                raise ValueError(f"alert log backup is not a regular file: {backup}")
            backup.unlink()
        os.replace(self.path, backup)
        try:
            backup.chmod(0o600)
        except OSError:
            pass

    def _append(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        line = serialized + b"\n"
        if len(serialized) > self.max_line_bytes:
            raise ValueError("alert payload exceeds maximum line size")
        self._rotate_if_needed(len(line))
        self._reject_symlink(self.path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        try:
            self._write_all(descriptor, line)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass
