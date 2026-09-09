from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from ..contracts import AnalysisReport, EventKind, Finding, SecurityEvent
from ..privacy_identity import PrivacyIdentity


RESPONSE_CONTEXT_VERSION = "1.1"
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
_PLAYBOOK_BY_CATEGORY = {
    "malware": "malware_triage",
    "integrity": "evidence_integrity_triage",
    "privilege": "privilege_triage",
    "persistence": "persistence_triage",
    "identity": "identity_triage",
    "network": "network_triage",
    "container": "container_triage",
    "vulnerability": "vulnerability_triage",
    "execution": "process_execution_triage",
    "file_integrity": "file_integrity_triage",
    "operational": "host_health_triage",
    "security": "general_incident_triage",
}


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


def build_resolution_target_handle(
    finding: Finding,
    *,
    privacy_identity: PrivacyIdentity,
) -> str:
    """Return an opaque identifier for endpoint-local remediation escrow.

    The handle itself is safe to cross the Response boundary. The corresponding raw
    target is never embedded in the network handoff and must remain in a private
    local escrow consumed only by the endpoint Response agent.
    """
    token = privacy_identity.identify_scoped(
        f"{finding.finding_id}\n{finding.subject}",
        "response-resolution-target-v1",
    )
    return f"qwrt-{token}"


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
    if category in {"identity", "privilege"}:
        hints.append("identity_activity_review")
    if category == "integrity":
        hints.append("evidence_chain_review")
    return list(dict.fromkeys(hints))


def _response_priority(finding: Finding) -> str:
    severity = finding.severity.value
    if severity == "critical" or finding.score >= 90.0:
        return "urgent"
    if severity == "high" or finding.score >= 70.0:
        return "elevated"
    return "routine"


def _evidence_strength(events: list[SecurityEvent]) -> str:
    kinds = {event.kind for event in events}
    sources = {event.source for event in events}
    if len(events) >= 3 and (len(kinds) >= 2 or len(sources) >= 2):
        return "strong"
    if len(events) >= 2 or len(kinds) >= 2 or len(sources) >= 2:
        return "corroborated"
    return "limited"


def _recommended_playbook(category: str) -> str:
    return _PLAYBOOK_BY_CATEGORY.get(category, "general_incident_triage")


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

    The only remediation-related value allowed across this boundary is an opaque
    resolution-target handle. It contains no path/PID/address/account identifier and
    has no executable authority. Any raw local target needed for later remediation
    remains in endpoint-local escrow outside this serialized network handoff.
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
        resolution_handle = build_resolution_target_handle(
            finding,
            privacy_identity=privacy_identity,
        )
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
                    "resolution_target_handle": resolution_handle,
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
                    "response_priority": _response_priority(finding),
                    "evidence_strength": _evidence_strength(matched),
                    "recommended_playbook": _recommended_playbook(category),
                    "operating_system": os_family,
                    "quietward_source_cycle_id": provenance_cycle,
                    "quietward_source_chain_hash": provenance_hash,
                },
            }
        )
    return payloads
