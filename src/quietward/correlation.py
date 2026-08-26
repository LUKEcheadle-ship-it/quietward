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
_HIGH_SIGNAL_MARKERS = {
    "reverse_shell", "web_shell", "credential_dumping", "credential_theft",
    "process_injection", "document_spawned_interpreter", "web_server_spawned_suspicious_shell",
    "server_spawned_suspicious_shell", "ransomware_recovery_inhibition",
    "event_log_clearing", "docker_socket_mount", "host_root_mount", "dangerous_container_config",
}
_GENERIC_ACTOR_NAMES = {
    "bash", "cmd", "cmd.exe", "java", "node", "node.exe", "powershell",
    "powershell.exe", "pwsh", "python", "python.exe", "python3", "sh",
    "svchost", "svchost.exe", "system",
}


def _normalized_process_name(value: object) -> str:
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        return ""
    return PurePath(text).name.casefold()[:128]


def _normalized_actor_name(value: object) -> str | None:
    name = str(value or "").strip().replace("\\", "/").rsplit("/", 1)[-1].casefold()
    if not name or name in _GENERIC_ACTOR_NAMES or len(name) > 200:
        return None
    return name


def _actor_keys(event: SecurityEvent) -> tuple[str, ...]:
    attributes = event.attributes or {}
    values: set[str] = set()
    for key in ("pid", "owner_pid"):
        try:
            pid = int(attributes.get(key) or 0)
        except (TypeError, ValueError):
            pid = 0
        if pid > 0:
            values.add(f"pid:{pid}")
    for key in ("owner_executable", "owner_command_name", "process_name", "command_name"):
        name = _normalized_actor_name(attributes.get(key))
        if name is not None:
            values.add(f"name:{name}")
    return tuple(sorted(values))


def _event_markers(event: SecurityEvent) -> set[str]:
    attrs = event.attributes or {}
    values: list[object] = []
    for key in ("suspicious_markers", "risk_markers", "security_markers", "owner_suspicious_markers"):
        raw = attrs.get(key)
        if raw is None:
            continue
        if isinstance(raw, str):
            values.append(raw)
        elif isinstance(raw, (list, tuple, set)):
            values.extend(raw)
    return {
        str(item).strip().casefold().replace("-", "_").replace(" ", "_")
        for item in values if str(item).strip()
    }


def _event_is_high_signal(event: SecurityEvent) -> bool:
    return event.kind in _HIGH_SIGNAL_KINDS or bool(_event_markers(event) & _HIGH_SIGNAL_MARKERS)


def _temporal_evidence_ids(events: list[SecurityEvent]) -> tuple[str, ...]:
    current_ids = {event.event_id for event in events}
    values: set[str] = set()
    for event in events:
        raw = event.attributes.get("temporal_context_event_ids")
        if raw is None:
            continue
        items = (raw,) if isinstance(raw, str) else raw
        try:
            for item in items:
                event_id = str(item).strip()
                if event_id and event_id not in current_ids:
                    values.add(event_id)
                    if len(values) >= 32:
                        return tuple(sorted(values))
        except TypeError:
            continue
    return tuple(sorted(values))


def _process_network_matches(events: list[SecurityEvent]) -> tuple[str, ...]:
    suspicious_processes: set[str] = set()
    network_processes: set[str] = set()
    for event in events:
        attrs = event.attributes or {}
        if event.kind is EventKind.PROCESS_START:
            if not _event_markers(event):
                continue
            for candidate in (attrs.get("command_name"), attrs.get("executable"), event.subject):
                name = _normalized_process_name(candidate)
                if name:
                    suspicious_processes.add(name)
        elif event.kind in {EventKind.OUTBOUND_CONNECTION, EventKind.NEW_LISTENING_PORT}:
            name = _normalized_process_name(attrs.get("process_name"))
            if name:
                network_processes.add(name)
    return tuple(sorted(suspicious_processes & network_processes))


class IncidentCorrelator:
    """Correlate exact subjects, same-actor signals, and bounded host attack chains."""

    def __init__(self, minimum_finding_score: float = 15.0) -> None:
        self.minimum_finding_score = minimum_finding_score

    def correlate(self, events: list[SecurityEvent], assessments: list[EventAssessment]) -> list[Finding]:
        by_id = {assessment.event_id: assessment for assessment in assessments}
        groups: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        by_host: dict[str, list[SecurityEvent]] = defaultdict(list)
        group_max_score: dict[tuple[str, str], float] = {}
        for event in events:
            groups[(event.host_id, event.subject)].append(event)
            by_host[event.host_id].append(event)
        for key, values in groups.items():
            group_max_score[key] = max(by_id[item.event_id].score for item in values)

        actor_events: dict[tuple[str, str], dict[str, SecurityEvent]] = defaultdict(dict)
        for event in events:
            for actor_key in _actor_keys(event):
                actor_events[(event.host_id, actor_key)][event.event_id] = event
        actor_canonical_subject: dict[tuple[str, str], str] = {}
        for actor, event_map in actor_events.items():
            values = tuple(event_map.values())
            subjects = {item.subject for item in values}
            kinds = {item.kind for item in values}
            if len(subjects) < 2 or len(kinds) < 2:
                continue
            host_id, _ = actor
            actor_canonical_subject[actor] = sorted(
                subjects,
                key=lambda subject: (-group_max_score.get((host_id, subject), 0.0), subject),
            )[0]

        findings: list[Finding] = []
        for (host_id, subject), grouped_events in sorted(groups.items()):
            related: dict[str, SecurityEvent] = {}
            related_subjects: set[str] = set()
            for event in grouped_events:
                for actor_key in _actor_keys(event):
                    actor = (host_id, actor_key)
                    if actor_canonical_subject.get(actor) != subject:
                        continue
                    for candidate in actor_events[actor].values():
                        if candidate.event_id in related or candidate.subject == subject:
                            continue
                        related[candidate.event_id] = candidate
                        related_subjects.add(candidate.subject)
            finding = self._subject_finding(host_id, subject, grouped_events, by_id, related, related_subjects)
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
        related: dict[str, SecurityEvent],
        related_subjects: set[str],
    ) -> Finding | None:
        grouped_events.sort(key=lambda item: (item.observed_at, item.event_id))
        group_assessments = [by_id[item.event_id] for item in grouped_events]
        max_score = max(item.score for item in group_assessments)
        distinct_kinds = len({item.kind for item in grouped_events})
        evidence_bonus = min(15.0, max(0, len(grouped_events) - 1) * 4.0)
        diversity_bonus = 10.0 if distinct_kinds >= 3 else 5.0 if distinct_kinds == 2 else 0.0
        cross_signal_bonus = min(12.0, 6.0 + 2.0 * max(0, len(related_subjects) - 1)) if related else 0.0
        combined = min(100.0, max_score + evidence_bonus + diversity_bonus + cross_signal_bonus)
        if combined < self.minimum_finding_score:
            return None

        evidence_values = list(grouped_events)
        evidence_values.extend(sorted(related.values(), key=lambda item: (item.observed_at, item.event_id)))
        evidence_ids_list = [item.event_id for item in evidence_values]
        temporal_ids = _temporal_evidence_ids(evidence_values)
        for temporal_id in temporal_ids:
            if temporal_id not in evidence_ids_list:
                evidence_ids_list.append(temporal_id)
        evidence_ids = tuple(evidence_ids_list)
        digest_input = "|".join([host_id, subject, *evidence_ids]).encode("utf-8")
        finding_id = "qwf-" + hashlib.sha256(digest_input).hexdigest()[:16]
        reasons: list[str] = []
        for assessment in group_assessments:
            reasons.extend(assessment.reasons)
        if evidence_bonus:
            reasons.append(f"correlation_evidence_bonus=+{evidence_bonus:.1f}")
        if diversity_bonus:
            reasons.append(f"correlation_diversity_bonus=+{diversity_bonus:.1f}")
        if cross_signal_bonus:
            reasons.append(f"cross_signal_actor_bonus=+{cross_signal_bonus:.1f}")
            reasons.append(f"cross_signal_related_subjects={len(related_subjects)}")
        if temporal_ids:
            reasons.append(f"temporal_context_evidence_ids={len(temporal_ids)}")
        kinds = ", ".join(sorted({item.kind.value for item in grouped_events}))
        related_text = f" Related same-actor evidence from {len(related_subjects)} additional subject(s) was correlated." if related_subjects else ""
        temporal_text = f" {len(temporal_ids)} prior-cycle evidence item(s) contributed bounded temporal context." if temporal_ids else ""
        return Finding(
            finding_id=finding_id,
            created_at=datetime.now(timezone.utc),
            host_id=host_id,
            subject=subject,
            title=f"Potential security incident involving {subject}",
            summary=f"Observed {len(grouped_events)} event(s) across {distinct_kinds} indicator type(s): {kinds}." + related_text + temporal_text,
            score=combined,
            severity=severity_for_score(combined),
            evidence_event_ids=evidence_ids,
            reasons=tuple(reasons),
        )

    def _host_chain_finding(self, host_id: str, host_events: list[SecurityEvent], by_id: dict[str, EventAssessment]) -> Finding | None:
        candidates = [event for event in host_events if event.kind in _PHASE_BY_KIND]
        if len(candidates) < 2:
            return None
        candidates.sort(key=lambda item: (item.observed_at, item.event_id))
        best_events: list[SecurityEvent] = []
        best_score = -1.0
        best_process_network_matches: tuple[str, ...] = ()
        best_high_signal_markers: tuple[str, ...] = ()
        left = 0
        for right, event in enumerate(candidates):
            while event.observed_at - candidates[left].observed_at > _ATTACK_CHAIN_WINDOW:
                left += 1
            window = candidates[left : right + 1]
            phases = {_PHASE_BY_KIND[item.kind] for item in window}
            max_score = max(by_id[item.event_id].score for item in window)
            has_high_signal = any(_event_is_high_signal(item) for item in window)
            high_signal_markers = tuple(sorted({marker for item in window for marker in (_event_markers(item) & _HIGH_SIGNAL_MARKERS)}))
            process_network_matches = _process_network_matches(window)
            execution_network_only = phases == {"execution", "network"}
            qualifies = (
                (len(phases) >= 3 and max_score >= 25.0)
                or (
                    len(phases) >= 2
                    and has_high_signal
                    and max_score >= 65.0
                    and (not execution_network_only or bool(process_network_matches))
                )
                or (len(phases) >= 2 and bool(process_network_matches) and max_score >= 50.0)
            )
            if not qualifies or len({item.subject for item in window}) < 2:
                continue
            phase_bonus = min(24.0, max(0, len(phases) - 1) * 7.0)
            evidence_bonus = min(10.0, max(0, len(window) - 2) * 2.5)
            corroboration_bonus = 12.0 if process_network_matches else 0.0
            chain_score = min(100.0, max_score + phase_bonus + evidence_bonus + corroboration_bonus)
            if chain_score > best_score or (chain_score == best_score and len(window) > len(best_events)):
                best_score = chain_score
                best_events = list(window)
                best_process_network_matches = process_network_matches
                best_high_signal_markers = high_signal_markers
        if not best_events or best_score < self.minimum_finding_score:
            return None
        phases = tuple(sorted({_PHASE_BY_KIND[item.kind] for item in best_events}))
        subjects = tuple(sorted({item.subject for item in best_events}))
        evidence_ids = tuple(item.event_id for item in best_events)
        digest_input = "|".join([host_id, "host_attack_chain", *phases, *evidence_ids]).encode("utf-8")
        finding_id = "qwf-chain-" + hashlib.sha256(digest_input).hexdigest()[:16]
        start, end = best_events[0].observed_at, best_events[-1].observed_at
        window_seconds = max(0, int((end - start).total_seconds()))
        reasons = [
            "cross_subject_host_attack_chain=true",
            f"attack_chain_window_seconds={window_seconds}",
            "attack_chain_phases=" + ",".join(phases),
            f"attack_chain_subject_count={len(subjects)}",
        ]
        if best_high_signal_markers:
            reasons.append("attack_chain_high_signal_markers=" + ",".join(best_high_signal_markers[:8]))
        if best_process_network_matches:
            reasons.append("process_network_corroboration=" + ",".join(best_process_network_matches))
            reasons.append("process_network_corroboration_bonus=+12.0")
        return Finding(
            finding_id=finding_id,
            created_at=datetime.now(timezone.utc),
            host_id=host_id,
            subject=f"host:{host_id}",
            title=f"Potential multi-stage attack on {host_id}",
            summary=f"Observed {len(best_events)} cross-subject events across {len(phases)} attack phases within {window_seconds} seconds: {', '.join(phases)}.",
            score=best_score,
            severity=severity_for_score(best_score),
            evidence_event_ids=evidence_ids,
            reasons=tuple(reasons),
        )
