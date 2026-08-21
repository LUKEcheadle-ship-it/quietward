from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import PurePath

from .contracts import EventAssessment, EventKind, Finding, SecurityEvent
from .scoring import severity_for_score


_ATTACK_CHAIN_WINDOW = timedelta(minutes=15)
_PHASE_BY_KIND: dict[EventKind, str] = {
    EventKind.AUTH_FAILURE: "identity",
    EventKind.ACCOUNT_CHANGE: "identity",
    EventKind.PROCESS_START: "execution",
    EventKind.EXECUTABLE_CREATED: "execution",
    EventKind.PRIVILEGE_ESCALATION: "privilege",
    EventKind.PERSISTENCE_CHANGE: "persistence",
    EventKind.NEW_LISTENING_PORT: "network",
    EventKind.OUTBOUND_CONNECTION: "network",
    EventKind.MALWARE_SIGNATURE: "malware",
    EventKind.YARA_MATCH: "malware",
    EventKind.SENSITIVE_FILE_CHANGE: "file_integrity",
    EventKind.FILE_CHANGE: "file_integrity",
    EventKind.CONTAINER_ESCAPE_INDICATOR: "container",
    EventKind.CONTAINER_CONFIGURATION_CHANGE: "container",
    EventKind.CONTAINER_CHANGE: "container",
    EventKind.SELF_INTEGRITY_CHANGE: "integrity",
    EventKind.EVIDENCE_INTEGRITY_FAILURE: "integrity",
    EventKind.PACKAGE_VULNERABILITY: "vulnerability",
    EventKind.CONFIGURATION_WEAKNESS: "vulnerability",
}
_HIGH_SIGNAL_KINDS = {
    EventKind.MALWARE_SIGNATURE,
    EventKind.YARA_MATCH,
    EventKind.CONTAINER_ESCAPE_INDICATOR,
    EventKind.EVIDENCE_INTEGRITY_FAILURE,
    EventKind.PRIVILEGE_ESCALATION,
    EventKind.PERSISTENCE_CHANGE,
}


def _normalized_process_name(value: object) -> str:
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        return ""
    return PurePath(text).name.casefold()[:128]


def _process_network_matches(events: list[SecurityEvent]) -> tuple[str, ...]:
    suspicious_processes: set[str] = set()
    network_processes: set[str] = set()
    for event in events:
        attrs = event.attributes or {}
        if event.kind is EventKind.PROCESS_START:
            markers = attrs.get("suspicious_markers") or attrs.get("risk_markers") or []
            if not markers:
                continue
            for candidate in (
                attrs.get("command_name"),
                attrs.get("executable"),
                event.subject,
            ):
                name = _normalized_process_name(candidate)
                if name:
                    suspicious_processes.add(name)
        elif event.kind in {EventKind.OUTBOUND_CONNECTION, EventKind.NEW_LISTENING_PORT}:
            name = _normalized_process_name(attrs.get("process_name"))
            if name:
                network_processes.add(name)
    return tuple(sorted(suspicious_processes & network_processes))


class IncidentCorrelator:
    """Correlate exact subjects plus bounded same-host multi-stage attack chains."""

    def __init__(self, minimum_finding_score: float = 15.0) -> None:
        self.minimum_finding_score = minimum_finding_score

    def correlate(
        self,
        events: list[SecurityEvent],
        assessments: list[EventAssessment],
    ) -> list[Finding]:
        by_id = {assessment.event_id: assessment for assessment in assessments}
        groups: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        by_host: dict[str, list[SecurityEvent]] = defaultdict(list)
        for event in events:
            groups[(event.host_id, event.subject)].append(event)
            by_host[event.host_id].append(event)

        findings: list[Finding] = []
        for (host_id, subject), grouped_events in sorted(groups.items()):
            finding = self._subject_finding(host_id, subject, grouped_events, by_id)
            if finding is not None:
                findings.append(finding)

        for host_id, host_events in sorted(by_host.items()):
            chain = self._host_chain_finding(host_id, host_events, by_id)
            if chain is not None:
                findings.append(chain)

        return findings

    def _subject_finding(
        self,
        host_id: str,
        subject: str,
        grouped_events: list[SecurityEvent],
        by_id: dict[str, EventAssessment],
    ) -> Finding | None:
        grouped_events.sort(key=lambda item: (item.observed_at, item.event_id))
        group_assessments = [by_id[item.event_id] for item in grouped_events]
        max_score = max(item.score for item in group_assessments)
        distinct_kinds = len({item.kind for item in grouped_events})
        evidence_bonus = min(15.0, max(0, len(grouped_events) - 1) * 4.0)
        diversity_bonus = (
            10.0 if distinct_kinds >= 3 else 5.0 if distinct_kinds == 2 else 0.0
        )
        combined = min(100.0, max_score + evidence_bonus + diversity_bonus)
        if combined < self.minimum_finding_score:
            return None

        evidence_ids = tuple(item.event_id for item in grouped_events)
        digest_input = "|".join([host_id, subject, *evidence_ids]).encode("utf-8")
        finding_id = "fsf-" + hashlib.sha256(digest_input).hexdigest()[:16]
        reasons: list[str] = []
        for assessment in group_assessments:
            reasons.extend(assessment.reasons)
        if evidence_bonus:
            reasons.append(f"correlation_evidence_bonus=+{evidence_bonus:.1f}")
        if diversity_bonus:
            reasons.append(f"correlation_diversity_bonus=+{diversity_bonus:.1f}")

        kinds = ", ".join(sorted({item.kind.value for item in grouped_events}))
        return Finding(
            finding_id=finding_id,
            created_at=datetime.now(timezone.utc),
            host_id=host_id,
            subject=subject,
            title=f"Potential security incident involving {subject}",
            summary=(
                f"Observed {len(grouped_events)} event(s) across "
                f"{distinct_kinds} indicator type(s): {kinds}."
            ),
            score=combined,
            severity=severity_for_score(combined),
            evidence_event_ids=evidence_ids,
            reasons=tuple(reasons),
        )

    def _host_chain_finding(
        self,
        host_id: str,
        host_events: list[SecurityEvent],
        by_id: dict[str, EventAssessment],
    ) -> Finding | None:
        candidates = [event for event in host_events if event.kind in _PHASE_BY_KIND]
        if len(candidates) < 2:
            return None
        candidates.sort(key=lambda item: (item.observed_at, item.event_id))

        best_events: list[SecurityEvent] = []
        best_score = -1.0
        best_process_network_matches: tuple[str, ...] = ()
        left = 0
        for right, event in enumerate(candidates):
            while (
                event.observed_at - candidates[left].observed_at
                > _ATTACK_CHAIN_WINDOW
            ):
                left += 1
            window = candidates[left : right + 1]
            phases = {_PHASE_BY_KIND[item.kind] for item in window}
            max_score = max(by_id[item.event_id].score for item in window)
            has_high_signal = any(item.kind in _HIGH_SIGNAL_KINDS for item in window)
            process_network_matches = _process_network_matches(window)

            # Three distinct attack phases are enough when at least one event is
            # materially suspicious. Two phases require either a high-signal typed
            # event or exact suspicious-process/network corroboration. The latter
            # uses only process names already present in read-only telemetry.
            qualifies = (
                len(phases) >= 3 and max_score >= 25.0
            ) or (
                len(phases) >= 2 and has_high_signal and max_score >= 65.0
            ) or (
                len(phases) >= 2 and bool(process_network_matches) and max_score >= 50.0
            )
            if not qualifies:
                continue

            cross_subject = len({item.subject for item in window}) >= 2
            if not cross_subject:
                continue

            phase_bonus = min(24.0, max(0, len(phases) - 1) * 7.0)
            evidence_bonus = min(10.0, max(0, len(window) - 2) * 2.5)
            corroboration_bonus = 12.0 if process_network_matches else 0.0
            chain_score = min(
                100.0,
                max_score + phase_bonus + evidence_bonus + corroboration_bonus,
            )
            if chain_score > best_score or (
                chain_score == best_score and len(window) > len(best_events)
            ):
                best_score = chain_score
                best_events = list(window)
                best_process_network_matches = process_network_matches

        if not best_events or best_score < self.minimum_finding_score:
            return None

        phases = tuple(sorted({_PHASE_BY_KIND[item.kind] for item in best_events}))
        subjects = tuple(sorted({item.subject for item in best_events}))
        evidence_ids = tuple(item.event_id for item in best_events)
        digest_input = "|".join(
            [host_id, "host_attack_chain", *phases, *evidence_ids]
        ).encode("utf-8")
        finding_id = "qwf-chain-" + hashlib.sha256(digest_input).hexdigest()[:16]
        start = best_events[0].observed_at
        end = best_events[-1].observed_at
        window_seconds = max(0, int((end - start).total_seconds()))
        reasons = [
            "cross_subject_host_attack_chain=true",
            f"attack_chain_window_seconds={window_seconds}",
            "attack_chain_phases=" + ",".join(phases),
            f"attack_chain_subject_count={len(subjects)}",
        ]
        if best_process_network_matches:
            reasons.append(
                "process_network_corroboration=" + ",".join(best_process_network_matches)
            )
            reasons.append("process_network_corroboration_bonus=+12.0")
        return Finding(
            finding_id=finding_id,
            created_at=datetime.now(timezone.utc),
            host_id=host_id,
            subject=f"host:{host_id}",
            title=f"Potential multi-stage attack on {host_id}",
            summary=(
                f"Observed {len(best_events)} cross-subject events across "
                f"{len(phases)} attack phases within {window_seconds} seconds: "
                f"{', '.join(phases)}."
            ),
            score=best_score,
            severity=severity_for_score(best_score),
            evidence_event_ids=evidence_ids,
            reasons=tuple(reasons),
        )
