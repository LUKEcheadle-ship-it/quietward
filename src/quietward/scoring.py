from __future__ import annotations

from math import log2
from typing import Any

from .contracts import EventAssessment, EventKind, SecurityEvent, Severity


BASE_WEIGHTS = {
    EventKind.MALWARE_SIGNATURE: 95.0,
    EventKind.YARA_MATCH: 82.0,
    EventKind.CONTAINER_ESCAPE_INDICATOR: 92.0,
    EventKind.SENSITIVE_FILE_CHANGE: 48.0,
    EventKind.EXECUTABLE_CREATED: 30.0,
    EventKind.PRIVILEGE_ESCALATION: 42.0,
    EventKind.AUTH_FAILURE: 8.0,
    EventKind.NEW_LISTENING_PORT: 28.0,
    EventKind.OUTBOUND_CONNECTION: 14.0,
    EventKind.PACKAGE_VULNERABILITY: 25.0,
    EventKind.PROCESS_START: 3.0,
    EventKind.FILE_CHANGE: 2.0,
    EventKind.CONFIGURATION_WEAKNESS: 22.0,
    EventKind.CONTAINER_CHANGE: 5.0,
    EventKind.CONTAINER_CONFIGURATION_CHANGE: 42.0,
    EventKind.ACCOUNT_CHANGE: 32.0,
    EventKind.PERSISTENCE_CHANGE: 44.0,
    EventKind.SELF_INTEGRITY_CHANGE: 58.0,
    EventKind.EVIDENCE_INTEGRITY_FAILURE: 90.0,
    EventKind.COLLECTOR_HEALTH: 0.0,
}

_MARKER_WEIGHTS: dict[str, float] = {
    "credential_dumping": 30.0,
    "credential_theft": 28.0,
    "credential_spray": 22.0,
    "reverse_shell": 30.0,
    "web_shell": 30.0,
    "process_injection": 30.0,
    "document_spawned_interpreter": 30.0,
    "server_spawned_suspicious_shell": 30.0,
    "web_server_spawned_suspicious_shell": 30.0,
    "ransomware_recovery_inhibition": 30.0,
    "event_log_clearing": 30.0,
    "defender_tamper_command": 20.0,
    "download_execute": 24.0,
    "download_and_execute": 24.0,
    "download_execute_chain": 24.0,
    "network_payload_retrieval": 20.0,
    "encoded_command": 18.0,
    "encoded_shell": 20.0,
    "encoded_shell_chain": 20.0,
    "living_off_the_land": 16.0,
    "living_off_the_land_pattern": 18.0,
    "lolbin": 16.0,
    "cryptominer": 22.0,
    "crypto_miner": 22.0,
    "cryptominer_indicator": 22.0,
    "network_listener_tool": 12.0,
    "volatile_directory_executable": 16.0,
    "user_writable_executable": 10.0,
    "user_writable_target": 10.0,
    "privileged_service": 18.0,
    "network_target": 10.0,
    "dangerous_container_config": 28.0,
    "privileged_container": 24.0,
    "docker_socket_mount": 28.0,
    "host_root_mount": 30.0,
    "sensitive_host_mount": 20.0,
    "sensitive_capability": 20.0,
    "host_pid": 20.0,
    "host_network": 14.0,
    "host_ipc": 14.0,
    "no_new_privileges_missing": 6.0,
    "restart_loop": 8.0,
    "unhealthy_container": 6.0,
    "suspicious_child_process": 14.0,
    "unexpected_interpreter": 14.0,
}

_HIGH_CONFIDENCE_MARKERS = {
    "credential_dumping", "credential_theft", "reverse_shell", "web_shell",
    "process_injection", "document_spawned_interpreter", "server_spawned_suspicious_shell",
    "web_server_spawned_suspicious_shell", "ransomware_recovery_inhibition",
    "event_log_clearing", "dangerous_container_config", "docker_socket_mount", "host_root_mount",
}


def severity_for_score(score: float) -> Severity:
    if score >= 85:
        return Severity.CRITICAL
    if score >= 65:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 15:
        return Severity.LOW
    return Severity.INFO


def _markers(attributes: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for key in ("suspicious_markers", "risk_markers", "security_markers", "owner_suspicious_markers"):
        raw = attributes.get(key)
        if raw is None:
            continue
        values = (raw,) if isinstance(raw, str) else raw
        try:
            for value in values:
                marker = str(value).strip().lower().replace("-", "_").replace(" ", "_")
                if marker:
                    result.add(marker)
        except TypeError:
            marker = str(raw).strip().lower().replace("-", "_").replace(" ", "_")
            if marker:
                result.add(marker)
    return result


def _integer_attribute(attributes: dict[str, Any], *names: str) -> int:
    for name in names:
        raw = attributes.get(name)
        if raw is None:
            continue
        try:
            return max(0, int(raw))
        except (TypeError, ValueError):
            continue
    return 0


class DeterministicRiskScorer:
    def score(self, event: SecurityEvent) -> EventAssessment:
        reasons: list[str] = []
        base = BASE_WEIGHTS[event.kind]
        score = base * event.confidence
        reasons.append(f"base:{event.kind.value}={base:.1f}")
        if event.confidence < 1:
            reasons.append(f"confidence_multiplier={event.confidence:.2f}")

        attrs = event.attributes
        for key, bonus, label in (
            ("known_bad_hash", 30.0, "known_bad_hash"),
            ("unsigned_executable", 15.0, "unsigned_executable"),
            ("external_destination", 10.0, "external_destination"),
            ("privileged_context", 12.0, "privileged_context"),
            ("persistence_indicator", 18.0, "persistence_indicator"),
            ("external_bind", 8.0, "external_bind"),
        ):
            if bool(attrs.get(key)):
                score += bonus
                reasons.append(f"{label}=+{bonus:g}")

        markers = _markers(attrs)
        if markers:
            raw_bonus = sum(_MARKER_WEIGHTS.get(marker, 10.0) for marker in markers)
            marker_bonus = min(30.0, raw_bonus)
            score += marker_bonus
            reasons.append(f"suspicious_markers=+{marker_bonus:.1f}")
            high_signal = sorted(markers & _HIGH_CONFIDENCE_MARKERS)
            if high_signal:
                reasons.append("high_signal_markers=" + ",".join(high_signal[:8]))
            if high_signal and event.confidence >= 0.8:
                before = score
                score = max(score, 65.0)
                if score > before:
                    reasons.append("high_confidence_behavior_floor=65.0")

        failed = _integer_attribute(attrs, "failed_count", "failure_count", "attempt_count")
        if failed > 1:
            bonus = min(25.0, 5.0 * log2(failed))
            score += bonus
            reasons.append(f"failed_count={failed}:+{bonus:.1f}")

        distinct_accounts = _integer_attribute(attrs, "distinct_accounts", "unique_accounts", "unique_users", "target_account_count", "target_count")
        source_failures = _integer_attribute(attrs, "source_failed_count", "source_failure_count", "source_attempt_count")
        spray_attempts = max(failed, source_failures)
        if event.kind is EventKind.AUTH_FAILURE and spray_attempts >= 10 and distinct_accounts >= 5:
            spray_bonus = min(22.0, 8.0 + 2.0 * log2(distinct_accounts))
            score += spray_bonus
            reasons.append(f"credential_spray_context={distinct_accounts}_accounts/{spray_attempts}_source_failures:+{spray_bonus:.1f}")
            if spray_attempts >= 32 and distinct_accounts >= 8 and event.confidence >= 0.8:
                before = score
                score = max(score, 65.0)
                if score > before:
                    reasons.append("credential_spray_high_priority_floor=65.0")

        cvss = float(attrs.get("cvss") or 0)
        if cvss > 0:
            bonus = min(30.0, cvss * 3)
            score += bonus
            reasons.append(f"cvss={cvss:.1f}:+{bonus:.1f}")

        deviation = float(attrs.get("baseline_deviation") or 0)
        if deviation > 0:
            bonus = min(20.0, max(0.0, deviation) * 20.0)
            score += bonus
            reasons.append(f"baseline_deviation={deviation:.2f}:+{bonus:.1f}")

        temporal_count = max(0, int(attrs.get("temporal_context_count") or 0))
        temporal_kinds = max(0, int(attrs.get("temporal_context_distinct_kinds") or 0))
        actor_match = bool(attrs.get("temporal_context_actor_match"))
        subject_match = bool(attrs.get("temporal_context_subject_match"))
        if temporal_count and temporal_kinds and (actor_match or subject_match):
            if actor_match:
                bonus = min(10.0, 4.0 + 2.0 * temporal_kinds)
                label = "temporal_actor_context"
            else:
                bonus = min(6.0, 2.0 + 2.0 * temporal_kinds)
                label = "temporal_subject_context"
            score += bonus
            reasons.append(f"{label}=+{bonus:.1f}")
            reasons.append(f"temporal_related_events={temporal_count};kinds={temporal_kinds}")

        score = max(0.0, min(100.0, score))
        return EventAssessment(event.event_id, score, severity_for_score(score), tuple(reasons))
