from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from ..contracts import AnalysisReport, EventKind, Finding, SecurityEvent
from ..privacy_identity import PrivacyIdentity


RESPONSE_CONTEXT_VERSION = "1.0"
_RESPONSE_HOST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_REASON_CODE = re.compile(r"^[a-z0-9_.:+-]{1,64}$")
_CHAIN_HASH = re.compile(r"^[0-9a-f]{64}$")

_CATEGORY_BY_KIND: dict[EventKind, str] = {
    EventKind.MALWARE_SIGNATURE: "malware",
    EventKind.YARA_MATCH: "malware",
    EventKind.PRIVILEGE_ESCALATION: "privilege",
    EventKind.AUTH_FAILURE: "identity",
    EventKind.ACCOUNT_CHANGE: "identity",
    EventKind.PERSISTENCE_CHANGE: "persistence",
    EventKind.NEW_LISTENING_PORT: "network",
    EventKind.OUTBOUND_CONNECTION: "network",
    EventKind.CONTAINER_ESCAPE_INDICATOR: "container",
    EventKind.CONTAINER_CHANGE: "container",
    EventKind.CONTAINER_CONFIGURATION_CHANGE: "container",
    EventKind.PACKAGE_VULNERABILITY: "vulnerability",
    EventKind.CONFIGURATION_WEAKNESS: "vulnerability",
    EventKind.PROCESS_START: "execution",
    EventKind.EXECUTABLE_CREATED: "execution",
    EventKind.SENSITIVE_FILE_CHANGE: "file_integrity",
    EventKind.FILE_CHANGE: "file_integrity",
    EventKind.SELF_INTEGRITY_CHANGE: "integrity",
    EventKind.EVIDENCE_INTEGRITY_FAILURE: "integrity",
    EventKind.COLLECTOR_HEALTH: "operational",
}
_CATEGORY_PRIORITY = (
    "malware",
    "integrity",
    "privilege",
    "persistence",
    "identity",
    "network",
    "container",
    "vulnerability",
    "execution",
    "file_integrity",
    "operational",
    "security",
)


def _category(events: Iterable[SecurityEvent]) -> str:
    categories = {_CATEGORY_BY_KIND.get(event.kind, "security") for event in events}
    for candidate in _CATEGORY_PRIORITY:
        if candidate in categories:
            return candidate
    return "security"


def _subject_type(events: Iterable[SecurityEvent]) -> str:
    kinds = {event.kind for event in events}
    if kinds & {EventKind.SENSITIVE_FILE_CHANGE, EventKind.FILE_CHANGE, EventKind.EXECUTABLE_CREATED}:
        return "file"
    if kinds & {EventKind.PROCESS_START, EventKind.PRIVILEGE_ESCALATION}:
        return "process"
    if kinds & {EventKind.NEW_LISTENING_PORT, EventKind.OUTBOUND_CONNECTION}:
        return "network"
    if kinds & {EventKind.PERSISTENCE_CHANGE}:
        return "persistence"
    if kinds & {EventKind.AUTH_FAILURE, EventKind.ACCOUNT_CHANGE}:
        return "identity"
    if kinds & {
        EventKind.CONTAINER_ESCAPE_INDICATOR,
        EventKind.CONTAINER_CHANGE,
        EventKind.CONTAINER_CONFIGURATION_CHANGE,
    }:
        return "container"
    return "host_or_other"


def _reason_codes(finding: Finding) -> list[str]:
    values: set[str] = set()
    for reason in finding.reasons:
        raw = str(reason).strip().casefold().split("=", 1)[0]
        if _SAFE_REASON_CODE.fullmatch(raw):
            values.add(raw)
        if len(values) >= 24:
            break
    return sorted(values)


def _investigation_hints(category: str) -> list[str]:
    hints = ["host_health"]
    if category in {"malware", "privilege", "persistence", "execution", "security"}:
        hints.append("process_inventory")
    if category == "network":
        hints.extend(["process_inventory", "network_snapshot"])
    if category in {"file_integrity", "malware"}:
        hints.append("artifact_metadata_review")
    return list(dict.fromkeys(hints))


def _coarse_os_family(value: str | None) -> str | None:
    text = (value or "").strip().casefold()
    if not text:
        return None
    if "windows" in text:
        return "Windows"
    if "linux" in text:
        return "Linux"
    if "darwin" in text or "macos" in text or "mac os" in text:
        return "Darwin"
    return "Unknown"


def _validate_provenance(
    source_cycle_id: int | None,
    source_chain_hash: str | None,
) -> tuple[int | None, str | None]:
    if source_cycle_id is None and source_chain_hash is None:
        return None, None
    if (
        not isinstance(source_cycle_id, int)
        or isinstance(source_cycle_id, bool)
        or source_cycle_id <= 0
    ):
        raise ValueError("Response handoff source cycle id is invalid")
    if not isinstance(source_chain_hash, str) or not _CHAIN_HASH.fullmatch(source_chain_hash):
        raise ValueError("Response handoff source evidence-chain hash is invalid")
    return source_cycle_id, source_chain_hash


def _validate_observation_only(report: AnalysisReport) -> None:
    if report.actions_executed != 0:
        raise ValueError("Response handoff requires an observation-only QuietWard report")
    if any(item.executable_in_current_mode for item in report.action_proposals):
        raise ValueError("Response handoff refuses executable QuietWard proposals")


def build_response_handoff_events(
    report: AnalysisReport,
    events: Iterable[SecurityEvent],
    *,
    privacy_identity: PrivacyIdentity,
    source_version: str | None = None,
    operating_system: str | None = None,
    source_cycle_id: int | None = None,
    source_chain_hash: str | None = None,
) -> list[dict[str, Any]]:
    """Build sanitized Response EventCreate payloads from QuietWard findings.

    This is a one-way data contract only. It does not make network requests, poll
    for actions, execute proposals, expose raw finding subjects, or grant Response
    authority back into the QuietWard process. A coarse OS family may cross the
    boundary so Response can enforce platform policy. Automated outbox handoffs may
    additionally carry the exact QuietWard evidence-chain cycle/hash for provenance.
    """
    _validate_observation_only(report)
    provenance_cycle, provenance_hash = _validate_provenance(
        source_cycle_id,
        source_chain_hash,
    )
    by_id = {event.event_id: event for event in events}
    payloads: list[dict[str, Any]] = []
    os_family = _coarse_os_family(operating_system)

    for finding in report.findings:
        if not _RESPONSE_HOST_ID.fullmatch(finding.host_id):
            raise ValueError("QuietWard host_id is not compatible with the Response host-id contract")
        matched = [
            by_id[event_id]
            for event_id in finding.evidence_event_ids
            if event_id in by_id
        ]
        matched.sort(key=lambda item: (item.observed_at, item.event_id))
        category = _category(matched)
        subject_type = _subject_type(matched)
        kinds = sorted({event.kind.value for event in matched})
        confidences = [event.confidence for event in matched]
        confidence = (
            sum(confidences) / len(confidences)
            if confidences
            else max(0.0, min(1.0, finding.score / 100.0))
        )
        subject_token = privacy_identity.identify_scoped(
            finding.subject,
            "response-subject-v1",
        )
        finding_token = privacy_identity.identify_scoped(
            finding.finding_id,
            "response-finding-v1",
        )
        # The exported event identity is installation-keyed through finding_token.
        # This keeps duplicate handling deterministic on one installation without
        # exposing the unkeyed internal QuietWard finding identifier.
        response_event_id = str(
            uuid5(
                NAMESPACE_URL,
                f"quietward-response:{finding.host_id}:{finding_token}",
            )
        )
        payloads.append(
            {
                "schema_version": "1.0",
                "event_id": response_event_id,
                "source": "quietward",
                "source_version": source_version,
                "host_id": finding.host_id,
                "host_name": None,
                "timestamp": finding.created_at.isoformat(),
                "event_type": f"quietward_{category}_finding",
                "category": category,
                "severity": finding.severity.value,
                "confidence": round(confidence, 4),
                "summary": (
                    f"QuietWard correlated {len(finding.evidence_event_ids)} evidence item(s) "
                    f"into a {finding.severity.value} {category} finding."
                ),
                "evidence": {
                    "event_count": len(finding.evidence_event_ids),
                    "event_kinds": kinds[:24],
                    "correlation_signal_codes": _reason_codes(finding),
                    "subject_hmac_sha256": subject_token,
                    "subject_type": subject_type,
                },
                "process": None,
                "file": None,
                "network": None,
                "persistence": None,
                "metadata": {
                    "quietward_response_context_version": RESPONSE_CONTEXT_VERSION,
                    "quietward_finding_hmac_sha256": finding_token,
                    "quietward_score": round(finding.score, 2),
                    "quietward_mode": report.mode,
                    "requires_human_approval": finding.requires_human_approval,
                    "observation_only_source": True,
                    "executable_authority": False,
                    "investigation_hints": _investigation_hints(category),
                    "operating_system": os_family,
                    "quietward_source_cycle_id": provenance_cycle,
                    "quietward_source_chain_hash": provenance_hash,
                },
            }
        )
    return payloads
