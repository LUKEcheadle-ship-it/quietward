from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .contracts import ActionProposal, ActionType


class RemediationRisk(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class RemediationStep:
    step_id: str
    description: str
    requires_administrator: bool
    reversible: bool
    system_state_change: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "description": self.description,
            "requires_administrator": self.requires_administrator,
            "reversible": self.reversible,
            "system_state_change": self.system_state_change,
        }


@dataclass(frozen=True, slots=True)
class RemediationPlan:
    plan_id: str
    finding_id: str
    platform: str
    title: str
    risk: RemediationRisk
    steps: tuple[RemediationStep, ...]
    rollback: tuple[str, ...]
    requires_explicit_approval: bool = True
    executable_in_current_mode: bool = False

    def __post_init__(self) -> None:
        if not self.requires_explicit_approval:
            raise ValueError("remediation plans must require explicit approval")
        if self.executable_in_current_mode:
            raise ValueError("observation-only remediation plans are not executable")
        if any(step.system_state_change and not step.reversible for step in self.steps):
            if self.risk not in {RemediationRisk.HIGH}:
                raise ValueError(
                    "irreversible state changes must be classified high risk"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "finding_id": self.finding_id,
            "platform": self.platform,
            "title": self.title,
            "risk": self.risk.value,
            "steps": [step.to_dict() for step in self.steps],
            "rollback": list(self.rollback),
            "requires_explicit_approval": self.requires_explicit_approval,
            "executable_in_current_mode": self.executable_in_current_mode,
            "actions_executed": 0,
        }


def plan_from_proposal(
    proposal: ActionProposal,
    *,
    platform: str,
) -> RemediationPlan:
    """Convert an existing proposal into a review-only remediation plan.

    This function intentionally produces no command, script, registry edit,
    process handle, or execution callback.
    """

    risk_by_action = {
        ActionType.NOTIFY: RemediationRisk.INFORMATIONAL,
        ActionType.COLLECT_DIAGNOSTIC: RemediationRisk.LOW,
        ActionType.QUARANTINE_ARTIFACT: RemediationRisk.HIGH,
        ActionType.STOP_PROCESS: RemediationRisk.HIGH,
        ActionType.STOP_SERVICE: RemediationRisk.HIGH,
        ActionType.BLOCK_NETWORK: RemediationRisk.HIGH,
        ActionType.ISOLATE_HOST: RemediationRisk.HIGH,
    }
    state_change = proposal.action_type not in {
        ActionType.NOTIFY,
        ActionType.COLLECT_DIAGNOSTIC,
    }
    steps = (
        RemediationStep(
            step_id="review-evidence",
            description="Review the normalized evidence and confirm the target.",
            requires_administrator=False,
            reversible=True,
            system_state_change=False,
        ),
        RemediationStep(
            step_id="prepare-rollback",
            description="Create and verify a platform-appropriate rollback point.",
            requires_administrator=state_change,
            reversible=True,
            system_state_change=False,
        ),
        RemediationStep(
            step_id="request-approval",
            description="Request explicit approval for the catalogued action.",
            requires_administrator=state_change,
            reversible=True,
            system_state_change=False,
        ),
    )
    return RemediationPlan(
        plan_id=f"remediation-{proposal.proposal_id}",
        finding_id=proposal.finding_id,
        platform=platform,
        title=f"Review proposed {proposal.action_type.value.replace('_', ' ')}",
        risk=risk_by_action[proposal.action_type],
        steps=steps,
        rollback=(
            "No system change is performed by this observation-only plan.",
        ),
        requires_explicit_approval=True,
        executable_in_current_mode=False,
    )
