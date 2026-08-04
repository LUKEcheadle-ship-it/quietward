from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from .contracts import (
    ActionProposal,
    ActionType,
    AnalysisReport,
    Finding,
    SecurityEvent,
    Severity,
)
from .correlation import IncidentCorrelator
from .policy import ObservationOnlyPolicy
from .scoring import DeterministicRiskScorer


DESTRUCTIVE_ACTIONS = {
    ActionType.QUARANTINE_ARTIFACT,
    ActionType.STOP_PROCESS,
    ActionType.STOP_SERVICE,
    ActionType.BLOCK_NETWORK,
    ActionType.ISOLATE_HOST,
}


class SentinelPipeline:
    def __init__(
        self,
        scorer: DeterministicRiskScorer | None = None,
        correlator: IncidentCorrelator | None = None,
        policy: ObservationOnlyPolicy | None = None,
    ) -> None:
        self.scorer = scorer or DeterministicRiskScorer()
        self.correlator = correlator or IncidentCorrelator()
        self.policy = policy or ObservationOnlyPolicy()

    def analyze(self, events: list[SecurityEvent]) -> AnalysisReport:
        assessments = [self.scorer.score(event) for event in events]
        findings = self.correlator.correlate(events, assessments) if events else []
        proposals = [proposal for finding in findings for proposal in self._proposals_for(finding)]
        for proposal in proposals:
            decision = self.policy.evaluate(proposal)
            if decision.allowed:
                raise RuntimeError("observation-only policy unexpectedly allowed an action")
        return AnalysisReport(
            generated_at=datetime.now(timezone.utc),
            mode=self.policy.mode,
            events_analyzed=len(events),
            assessments=tuple(assessments),
            findings=tuple(findings),
            action_proposals=tuple(proposals),
            actions_executed=0,
        )

    def _proposals_for(self, finding: Finding) -> list[ActionProposal]:
        action_types: list[ActionType] = [ActionType.NOTIFY]
        if finding.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}:
            action_types.append(ActionType.COLLECT_DIAGNOSTIC)
        if finding.severity in {Severity.HIGH, Severity.CRITICAL}:
            if finding.subject.startswith("/"):
                action_types.append(ActionType.QUARANTINE_ARTIFACT)
            else:
                action_types.append(ActionType.ISOLATE_HOST)

        proposals: list[ActionProposal] = []
        for action_type in action_types:
            digest = hashlib.sha256(
                f"{finding.finding_id}|{action_type.value}|{finding.subject}".encode("utf-8")
            ).hexdigest()[:16]
            proposals.append(
                ActionProposal(
                    proposal_id="fsp-" + digest,
                    finding_id=finding.finding_id,
                    action_type=action_type,
                    target=finding.subject if action_type != ActionType.ISOLATE_HOST else finding.host_id,
                    reason=f"Proposed because finding severity is {finding.severity.value}.",
                    destructive=action_type in DESTRUCTIVE_ACTIONS,
                    requires_approval=True,
                    executable_in_current_mode=False,
                )
            )
        return proposals
