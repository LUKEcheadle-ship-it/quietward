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

# Marker weights are deliberately bounded and deterministic. Unknown markers retain
# a small generic contribution so existing collectors stay compatible, while
# well-known multi-stage behaviors receive stronger priority.
_MARKER_WEIGHTS: dict[str, float] = {
    "credential_dumping": 30.0,
    "credential_theft": 28.0,
    "reverse_shell": 32.0,
    "web_shell": 30.0,
    "process_injection": 30.0,
    "download_execute": 24.0,
    "download_and_execute": 24.0,
    "encoded_command": 18.0,
    "encoded_shell": 20.0,
    "living_off_the_land": 16.0,
    "lolbin": 16.0,
    "cryptominer": 22.0,
    "crypto_miner": 22.0,
    "dangerous_container_config": 28.0,
    "privileged_container": 24.0,
    "docker_socket_mount": 28.0,
    "suspicious_child_process": 14.0,
    "unexpected_interpreter": 14.0,
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


def _normalized_markers(value: Any) -> tuple[str, ...]:
    if not value:
        return ()
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, (list, tuple, set)):
        candidates = list(value)
    else:
        return ()
    normalized = {
        str(item).strip().lower().replace("-", "_").replace(" ", "_")
        for item in candidates
        if str(item).strip()
    }
    return tuple(sorted(normalized))


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

        markers = _normalized_markers(
            attrs.get("suspicious_markers")
            or attrs.get("risk_markers")
            or attrs.get("security_markers")
        )
        if markers:
            raw_bonus = 0.0
            high_signal: list[str] = []
            for marker in markers:
                weight = _MARKER_WEIGHTS.get(marker, 10.0)
                raw_bonus += weight
                if marker in _MARKER_WEIGHTS:
                    high_signal.append(marker)
            marker_bonus = min(45.0, raw_bonus)
            score += marker_bonus
            reasons.append(f"suspicious_markers=+{marker_bonus:.1f}")
            if high_signal:
                reasons.append("high_signal_markers=" + ",".join(high_signal[:8]))

        failed = _integer_attribute(attrs, "failed_count", "failure_count", "attempt_count")
        if failed > 1:
            bonus = min(25.0, 5.0 * log2(failed))
            score += bonus
            reasons.append(f"failed_count={failed}:+{bonus:.1f}")

        distinct_accounts = _integer_attribute(
            attrs,
            "distinct_accounts",
            "unique_accounts",
            "unique_users",
            "target_account_count",
            "target_count",
        )
        if event.kind is EventKind.AUTH_FAILURE and failed >= 10 and distinct_accounts >= 5:
            spray_bonus = min(22.0, 8.0 + 2.0 * log2(distinct_accounts))
            score += spray_bonus
            reasons.append(
                f"credential_spray_context={distinct_accounts}_accounts:+{spray_bonus:.1f}"
            )

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

        score = max(0.0, min(100.0, score))
        return EventAssessment(
            event.event_id,
            score,
            severity_for_score(score),
            tuple(reasons),
        )
