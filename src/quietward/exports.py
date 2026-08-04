from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


_SENSITIVE_KEY_TOKENS = (
    "address",
    "path",
    "user",
    "name",
    "target",
    "home",
    "subject",
)
_SAFE_STRING_KEYS = {
    "algorithm",
    "category",
    "change_type",
    "collector_version",
    "destination_scope",
    "health_status",
    "kind",
    "message_class",
    "protocol",
    "rule",
    "scanner",
    "severity",
    "signature",
    "source",
    "status",
    "suite",
    "vulnerability_id",
}
_SAFE_STRING_LIST_KEYS = {
    "changed_fields",
    "risk_markers",
    "security_markers",
    "suspicious_markers",
}


def _stable_export_hash(value: object) -> str:
    return hashlib.sha256(
        b"quietward-incident-export-v1\0"
        + str(value).encode("utf-8", errors="replace")
    ).hexdigest()[:20]


def _sanitize_attributes(
    value: object,
    *,
    key_name: str | None = None,
) -> object:
    if isinstance(value, dict):
        result: dict[str, object] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            lowered = key.lower()
            if lowered == "note":
                continue
            if (
                key.endswith("_hash")
                or key.endswith("_sha256")
                or key.endswith("_persisted")
            ):
                result[key] = _sanitize_attributes(item, key_name=key)
                continue
            if any(token in lowered for token in _SENSITIVE_KEY_TOKENS):
                if isinstance(item, (str, int, float)):
                    result[f"{key}_hash"] = _stable_export_hash(item)
                elif isinstance(item, (list, tuple)):
                    result[f"{key}_hashes"] = [
                        _stable_export_hash(entry) for entry in item
                    ]
                else:
                    result[f"{key}_redacted"] = True
                continue
            result[key] = _sanitize_attributes(item, key_name=key)
        return result
    if isinstance(value, (list, tuple)):
        if key_name in _SAFE_STRING_LIST_KEYS:
            return [
                str(item)[:200]
                if isinstance(item, str)
                else _sanitize_attributes(item)
                for item in value
            ]
        return [
            _sanitize_attributes(item, key_name=key_name)
            for item in value
        ]
    if isinstance(value, str):
        if key_name in _SAFE_STRING_KEYS or (key_name or "").endswith(
            ("_hash", "_sha256")
        ):
            return value[:500]
        return {"value_hash": _stable_export_hash(value)}
    return value


def build_redacted_incident_export(bundle: dict[str, Any]) -> dict[str, Any]:
    finding = dict(bundle["finding"])
    finding_id = str(finding["finding_id"])
    events: list[dict[str, Any]] = []
    for raw_event in bundle.get("events", []):
        event = dict(raw_event)
        events.append(
            {
                "event_id": event.get("event_id"),
                "observed_at": event.get("observed_at"),
                "host_id": event.get("host_id"),
                "source": event.get("source"),
                "kind": event.get("kind"),
                "subject_hash": _stable_export_hash(event.get("subject")),
                "attributes": _sanitize_attributes(
                    event.get("attributes") or {}
                ),
                "confidence": event.get("confidence"),
                "assessment": _sanitize_attributes(
                    event.get("assessment") or {}
                ),
            }
        )
    proposals: list[dict[str, Any]] = []
    for raw_proposal in bundle.get("proposals", []):
        proposal = dict(raw_proposal)
        proposals.append(
            {
                "proposal_id": proposal.get("proposal_id"),
                "finding_id": proposal.get("finding_id"),
                "action_type": proposal.get("action_type"),
                "target_hash": _stable_export_hash(proposal.get("target")),
                "reason_included": False,
                "destructive": bool(proposal.get("destructive")),
                "requires_approval": bool(
                    proposal.get("requires_approval", True)
                ),
                "executable_in_current_mode": bool(
                    proposal.get("executable_in_current_mode", False)
                ),
            }
        )
    review = dict(bundle.get("review") or {})
    chain = dict(bundle.get("evidence_chain") or {})
    return {
        "export_version": "quietward-redacted-incident-v1",
        "generated_at": bundle.get("generated_at"),
        "finding": {
            "finding_id": finding_id,
            "created_at": finding.get("created_at"),
            "host_id": finding.get("host_id"),
            "subject_hash": _stable_export_hash(finding.get("subject")),
            "title": f"QuietWard incident {finding_id}",
            "summary": (
                f"{len(events)} normalized evidence event(s) are included in this "
                "redacted local export."
            ),
            "score": finding.get("score"),
            "severity": finding.get("severity"),
            "evidence_event_ids": list(
                finding.get("evidence_event_ids") or []
            ),
            "reason_hashes": [
                _stable_export_hash(reason)
                for reason in finding.get("reasons") or []
            ],
            "requires_human_approval": bool(
                finding.get("requires_human_approval", True)
            ),
        },
        "review": {
            "state": review.get("state") or "open",
            "suppress_until": review.get("suppress_until"),
            "updated_at": review.get("updated_at"),
            "analyst_note_included": False,
        },
        "events": events,
        "proposals": proposals,
        "evidence_chain": {
            "valid": chain.get("valid"),
            "cycles_checked": chain.get("cycles_checked"),
            "last_chain_hash": chain.get("last_chain_hash"),
            "anchor_cycle": chain.get("anchor_cycle"),
            "cryptographically_signed": chain.get(
                "cryptographically_signed"
            ),
            "signature_algorithm": chain.get("signature_algorithm"),
            "signature_key_id": chain.get("signature_key_id"),
            "signatures_checked": chain.get("signatures_checked"),
        },
        "privacy": {
            "subjects_redacted": True,
            "arbitrary_strings_hashed": True,
            "finding_reasons_hashed": True,
            "proposal_reasons_included": False,
            "analyst_notes_included": False,
            "raw_local_addresses_included": False,
            "raw_remote_addresses_included": False,
            "actions_executed": 0,
        },
    }


def render_incident_markdown(value: dict[str, Any]) -> str:
    finding = value["finding"]
    review = value["review"]
    chain = value["evidence_chain"]
    lines = [
        f"# QuietWard incident {finding['finding_id']}",
        "",
        f"- Severity: {finding.get('severity')}",
        f"- Score: {finding.get('score')}",
        f"- State: {review.get('state')}",
        f"- Subject hash: `{finding.get('subject_hash')}`",
        f"- Evidence events: {len(value.get('events', []))}",
        f"- Chain valid: {chain.get('valid')}",
        f"- Cryptographically signed: {chain.get('cryptographically_signed')}",
        "",
        finding.get("summary") or "",
        "",
        "## Evidence",
        "",
    ]
    for event in value.get("events", []):
        lines.extend(
            [
                f"### {event.get('event_id')}",
                "",
                f"- Kind: {event.get('kind')}",
                f"- Source: {event.get('source')}",
                f"- Subject hash: `{event.get('subject_hash')}`",
                f"- Observed: {event.get('observed_at')}",
                "",
                "```json",
                json.dumps(
                    event.get("attributes") or {},
                    indent=2,
                    sort_keys=True,
                ),
                "```",
                "",
            ]
        )
    lines.extend(
        [
            "## Safety",
            "",
            "- This export is redacted.",
            "- Free-text values are hashed unless explicitly allowlisted.",
            "- Analyst notes and proposal reasons are excluded.",
            "- No action was executed.",
            "",
        ]
    )
    return "\n".join(lines)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError("incident export write made no progress")
        written += count


def write_private_incident_export(
    path: Path,
    value: dict[str, Any],
    *,
    output_format: str = "json",
    force: bool = False,
) -> dict[str, Any]:
    path = path.expanduser()
    if output_format not in {"json", "markdown"}:
        raise ValueError("incident export format must be json or markdown")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError("incident export path may not be a symlink")
    if path.exists() and not force:
        raise FileExistsError(f"refusing to overwrite existing export: {path}")

    if output_format == "json":
        payload = (
            json.dumps(value, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
    else:
        payload = (render_incident_markdown(value) + "\n").encode("utf-8")

    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        try:
            _write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        path.chmod(0o600)
        try:
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            pass
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return {
        "path": str(path),
        "format": output_format,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "mode": "0600",
        "redacted": True,
        "actions_executed": 0,
    }
