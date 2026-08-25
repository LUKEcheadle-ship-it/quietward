from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class EventKind(StrEnum):
    MALWARE_SIGNATURE = "malware_signature"
    YARA_MATCH = "yara_match"
    CONTAINER_ESCAPE_INDICATOR = "container_escape_indicator"
    SENSITIVE_FILE_CHANGE = "sensitive_file_change"
    EXECUTABLE_CREATED = "executable_created"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    AUTH_FAILURE = "auth_failure"
    NEW_LISTENING_PORT = "new_listening_port"
    OUTBOUND_CONNECTION = "outbound_connection"
    PACKAGE_VULNERABILITY = "package_vulnerability"
    PROCESS_START = "process_start"
    PROCESS_BURST = "process_burst"
    ENCODED_COMMAND = "encoded_command"
    SUSPICIOUS_FILE_CHURN = "suspicious_file_churn"
    PORT_SCAN = "port_scan"
    BEACON = "beacon"
    FILE_CHANGE = "file_change"
    CONFIGURATION_WEAKNESS = "configuration_weakness"
    CONTAINER_CHANGE = "container_change"
    CONTAINER_CONFIGURATION_CHANGE = "container_configuration_change"
    ACCOUNT_CHANGE = "account_change"
    PERSISTENCE_CHANGE = "persistence_change"
    SELF_INTEGRITY_CHANGE = "self_integrity_change"
    EVIDENCE_INTEGRITY_FAILURE = "evidence_integrity_failure"
    COLLECTOR_HEALTH = "collector_health"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(StrEnum):
    NOTIFY = "notify"
    COLLECT_DIAGNOSTIC = "collect_diagnostic"
    QUARANTINE_ARTIFACT = "quarantine_artifact"
    STOP_PROCESS = "stop_process"
    STOP_SERVICE = "stop_service"
    BLOCK_NETWORK = "block_network"
    ISOLATE_HOST = "isolate_host"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    event_id: str
    observed_at: datetime
    host_id: str
    source: str
    kind: EventKind
    subject: str
    attributes: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if not self.event_id.strip():
            raise ValueError("event_id must not be empty")
        if not self.host_id.strip():
            raise ValueError("host_id must not be empty")
        if not self.source.strip():
            raise ValueError("source must not be empty")
        if not self.subject.strip():
            raise ValueError("subject must not be empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SecurityEvent":
        raw_time = value.get("observed_at")
        if not isinstance(raw_time, str):
            raise ValueError("observed_at must be an ISO-8601 string")
        timestamp = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
        return cls(
            event_id=str(value.get("event_id") or ""),
            observed_at=timestamp,
            host_id=str(value.get("host_id") or ""),
            source=str(value.get("source") or ""),
            kind=EventKind(str(value.get("kind") or "")),
            subject=str(value.get("subject") or ""),
            attributes=dict(value.get("attributes") or {}),
            confidence=float(value.get("confidence", 1.0)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "observed_at": self.observed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "host_id": self.host_id,
            "source": self.source,
            "kind": self.kind.value,
            "subject": self.subject,
            "attributes": self.attributes,
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class EventAssessment:
    event_id: str
    score: float
    severity: Severity
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"event_id": self.event_id, "score": round(self.score, 2), "severity": self.severity.value, "reasons": list(self.reasons)}


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    created_at: datetime
    host_id: str
    subject: str
    title: str
    summary: str
    score: float
    severity: Severity
    evidence_event_ids: tuple[str, ...]
    reasons: tuple[str, ...]
    requires_human_approval: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "created_at": self.created_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "host_id": self.host_id,
            "subject": self.subject,
            "title": self.title,
            "summary": self.summary,
            "score": round(self.score, 2),
            "severity": self.severity.value,
            "evidence_event_ids": list(self.evidence_event_ids),
            "reasons": list(self.reasons),
            "requires_human_approval": self.requires_human_approval,
        }


@dataclass(frozen=True, slots=True)
class ActionProposal:
    proposal_id: str
    finding_id: str
    action_type: ActionType
    target: str
    reason: str
    destructive: bool
    requires_approval: bool = True
    executable_in_current_mode: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "finding_id": self.finding_id,
            "action_type": self.action_type.value,
            "target": self.target,
            "reason": self.reason,
            "destructive": self.destructive,
            "requires_approval": self.requires_approval,
            "executable_in_current_mode": self.executable_in_current_mode,
        }


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    generated_at: datetime
    mode: str
    events_analyzed: int
    assessments: tuple[EventAssessment, ...]
    findings: tuple[Finding, ...]
    action_proposals: tuple[ActionProposal, ...]
    actions_executed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "mode": self.mode,
            "events_analyzed": self.events_analyzed,
            "assessments": [item.to_dict() for item in self.assessments],
            "findings": [item.to_dict() for item in self.findings],
            "action_proposals": [item.to_dict() for item in self.action_proposals],
            "actions_executed": self.actions_executed,
        }
