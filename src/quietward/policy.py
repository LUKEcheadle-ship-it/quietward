from __future__ import annotations

from dataclasses import dataclass

from .contracts import ActionProposal


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason: str


class ObservationOnlyPolicy:
    """v0.1 policy: proposals may be emitted, but no action may execute."""

    mode = "observe_only"

    def evaluate(self, proposal: ActionProposal) -> PolicyDecision:
        return PolicyDecision(
            allowed=False,
            reason=(
                "Action execution is disabled in observation-only mode. "
                "A future signed approval and bounded executor are required."
            ),
        )
