from __future__ import annotations

from typing import Any

from ..contracts import Finding


MAX_EXPLANATION_CHARS = 4000
MAX_STEP_CHARS = 500


def build_forge_explanation_request(finding: Finding) -> dict[str, Any]:
    """Create the narrow advisory-only envelope sent to a Forge micro-LLM worker."""
    return {
        "contract_version": "quietward-explanation-v1",
        "task_type": "security_incident_explanation",
        "capability": "advisory_only",
        "finding": finding.to_dict(),
        "constraints": {
            "scanner_evidence_is_authoritative": True,
            "may_execute_actions": False,
            "may_claim_malware_without_scanner_evidence": False,
            "requires_human_approval": True,
            "max_explanation_chars": MAX_EXPLANATION_CHARS,
            "max_recommended_steps": 5,
        },
    }


def validate_forge_explanation_response(value: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    explanation = value.get("explanation")
    steps = value.get("recommended_next_steps")
    uncertainty = value.get("uncertainty")
    if not isinstance(explanation, str) or not explanation.strip():
        errors.append("explanation must be a non-empty string")
    elif len(explanation) > MAX_EXPLANATION_CHARS:
        errors.append("explanation exceeds maximum length")
    if not isinstance(steps, list) or not all(
        isinstance(item, str) and item.strip() for item in steps
    ):
        errors.append(
            "recommended_next_steps must be a list of non-empty strings"
        )
    elif len(steps) > 5:
        errors.append("recommended_next_steps exceeds maximum count")
    elif any(len(item) > MAX_STEP_CHARS for item in steps):
        errors.append("a recommended step exceeds maximum length")
    if not isinstance(uncertainty, str) or not uncertainty.strip():
        errors.append("uncertainty must be a non-empty string")
    if value.get("action_authorized") is True:
        errors.append("micro-LLM responses cannot authorize actions")
    return errors
