from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timezone

from .contracts import EventAssessment, Finding, SecurityEvent
from .scoring import severity_for_score


class IncidentCorrelator:
    """Groups evidence by host and subject and adds a bounded correlation bonus."""

    def __init__(self, minimum_finding_score: float = 15.0) -> None:
        self.minimum_finding_score = minimum_finding_score

    def correlate(
        self,
        events: list[SecurityEvent],
        assessments: list[EventAssessment],
    ) -> list[Finding]:
        by_id = {assessment.event_id: assessment for assessment in assessments}
        groups: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        for event in events:
            groups[(event.host_id, event.subject)].append(event)

        findings: list[Finding] = []
        for (host_id, subject), grouped_events in sorted(groups.items()):
            grouped_events.sort(key=lambda item: (item.observed_at, item.event_id))
            group_assessments = [by_id[item.event_id] for item in grouped_events]
            max_score = max(item.score for item in group_assessments)
            distinct_kinds = len({item.kind for item in grouped_events})
            evidence_bonus = min(15.0, max(0, len(grouped_events) - 1) * 4.0)
            diversity_bonus = 10.0 if distinct_kinds >= 3 else 5.0 if distinct_kinds == 2 else 0.0
            combined = min(100.0, max_score + evidence_bonus + diversity_bonus)
            if combined < self.minimum_finding_score:
                continue

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
            findings.append(
                Finding(
                    finding_id=finding_id,
                    created_at=datetime.now(timezone.utc),
                    host_id=host_id,
                    subject=subject,
                    title=f"Potential security incident involving {subject}",
                    summary=f"Observed {len(grouped_events)} event(s) across {distinct_kinds} indicator type(s): {kinds}.",
                    score=combined,
                    severity=severity_for_score(combined),
                    evidence_event_ids=evidence_ids,
                    reasons=tuple(reasons),
                )
            )
        return findings
