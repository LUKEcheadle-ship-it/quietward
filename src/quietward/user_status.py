from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

ACTIVE_REVIEW_STATES = {"open", "acknowledged"}
HEALTHY_CYCLE_STATUSES = {"ok", "completed", "healthy", "success"}


@dataclass(frozen=True, slots=True)
class UserStatusAssessment:
    level: str
    label: str
    summary: str
    reasons: tuple[str, ...]
    recommended_action: str
    active_critical: int
    active_high: int
    active_medium: int
    evaluated_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "level": self.level,
            "label": self.label,
            "summary": self.summary,
            "reasons": list(self.reasons),
            "recommended_action": self.recommended_action,
            "active_findings": {
                "critical": self.active_critical,
                "high": self.active_high,
                "medium": self.active_medium,
            },
            "evaluated_at": self.evaluated_at.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "actions_executed": 0,
        }


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _active_counts(findings: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    latest: dict[tuple[str, str], Mapping[str, Any]] = {}
    fallback_index = 0
    for finding in findings:
        host = str(finding.get("host_id") or "")
        subject = str(finding.get("subject") or "")
        if host or subject:
            key = (host, subject)
        else:
            fallback_index += 1
            key = ("__unknown__", str(finding.get("finding_id") or fallback_index))
        existing = latest.get(key)
        if existing is None:
            latest[key] = finding
            continue
        current_time = _parse_timestamp(finding.get("created_at"))
        existing_time = _parse_timestamp(existing.get("created_at"))
        if current_time is not None and (
            existing_time is None or current_time >= existing_time
        ):
            latest[key] = finding

    counts = {"critical": 0, "high": 0, "medium": 0}
    for finding in latest.values():
        severity = str(finding.get("severity") or "").casefold()
        review = finding.get("review")
        state = "open"
        if isinstance(review, Mapping):
            state = str(review.get("state") or "open").casefold()
        if state not in ACTIVE_REVIEW_STATES or severity not in counts:
            continue
        counts[severity] += 1
    return counts


def assess_user_status(
    summary: Mapping[str, Any],
    findings: Iterable[Mapping[str, Any]],
    *,
    collector_errors: Iterable[str] = (),
    defender: Mapping[str, Any] | None = None,
    coverage: Mapping[str, Any] | None = None,
    now: datetime | None = None,
    stale_after_seconds: float = 300.0,
) -> UserStatusAssessment:
    if stale_after_seconds <= 0:
        raise ValueError("stale_after_seconds must be positive")
    timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    counts = _active_counts(findings)
    urgent: list[str] = []
    review: list[str] = []

    actions = int(summary.get("actions_executed", 0) or 0)
    if actions != 0:
        urgent.append("The safety invariant reports that an action was executed.")

    chain = summary.get("evidence_chain")
    if isinstance(chain, Mapping) and chain.get("valid") is False:
        urgent.append("The local evidence integrity check failed.")

    if counts["critical"]:
        urgent.append(
            f"{counts['critical']} active critical finding"
            + (" requires" if counts["critical"] == 1 else "s require")
            + " immediate review."
        )

    if defender is not None:
        threats = int(defender.get("active_threat_count", 0) or 0)
        if threats:
            urgent.append(
                f"Microsoft Defender reports {threats} active threat"
                + ("." if threats == 1 else "s.")
            )
        if defender.get("antivirus_enabled") is False:
            review.append("Microsoft Defender antivirus is reported as disabled.")
        if defender.get("real_time_protection_enabled") is False:
            review.append("Microsoft Defender real-time protection is reported as disabled.")

    last_cycle = summary.get("last_cycle")
    if not isinstance(last_cycle, Mapping):
        review.append("Monitoring has not completed its first observation cycle.")
    else:
        cycle_status = str(last_cycle.get("status") or "").casefold()
        if cycle_status not in HEALTHY_CYCLE_STATUSES:
            review.append("The latest monitoring cycle did not report a healthy completion.")
        completed_at = _parse_timestamp(last_cycle.get("completed_at"))
        if completed_at is None:
            review.append("The latest monitoring cycle has no valid completion time.")
        elif (timestamp - completed_at).total_seconds() > stale_after_seconds:
            review.append("Monitoring data is older than the configured freshness window.")
        if int(last_cycle.get("actions_executed", 0) or 0) != 0:
            urgent.append("The latest monitoring cycle reports an executed action.")
        if last_cycle.get("error"):
            review.append("The latest monitoring cycle reported an error.")

    if isinstance(coverage, Mapping):
        operational = coverage.get("operationally_healthy")
        legacy_incomplete = operational is None and coverage.get("resolution_safe") is False
        if operational is False or legacy_incomplete:
            degraded = int(coverage.get("degraded_required", coverage.get("degraded_count", 0)) or 0)
            if degraded > 0:
                review.append(
                    f"Monitoring coverage is degraded across {degraded} required observation "
                    + ("domain." if degraded == 1 else "domains.")
                )
            else:
                review.append("Required monitoring coverage is degraded.")
            review.append("QuietWard will not resolve incidents from absence until required coverage recovers.")

    errors = tuple(str(item).strip() for item in collector_errors if str(item).strip())
    if errors:
        review.append(
            f"The latest collector snapshot reports {len(errors)} warning"
            + ("." if len(errors) == 1 else "s.")
        )
    if counts["high"]:
        review.append(
            f"{counts['high']} active high-severity finding"
            + (" needs" if counts["high"] == 1 else "s need")
            + " review."
        )
    if counts["medium"]:
        review.append(
            f"{counts['medium']} active medium-severity finding"
            + (" is" if counts["medium"] == 1 else "s are")
            + " waiting for review."
        )

    if urgent:
        return UserStatusAssessment(
            level="urgent",
            label="Urgent",
            summary="QuietWard found a condition that should be reviewed immediately.",
            reasons=tuple(dict.fromkeys((*urgent, *review))),
            recommended_action=(
                "Open the critical finding details and verify Microsoft Defender status. "
                "Do not delete files or change system settings until the evidence is understood."
            ),
            active_critical=counts["critical"],
            active_high=counts["high"],
            active_medium=counts["medium"],
            evaluated_at=timestamp,
        )
    if review:
        return UserStatusAssessment(
            level="review_recommended",
            label="Review recommended",
            summary="QuietWard is running, but one or more items need your attention.",
            reasons=tuple(dict.fromkeys(review)),
            recommended_action=(
                "Review the listed findings and collector warnings. Mark known activity as "
                "expected only after confirming it is legitimate."
            ),
            active_critical=0,
            active_high=counts["high"],
            active_medium=counts["medium"],
            evaluated_at=timestamp,
        )
    return UserStatusAssessment(
        level="normal",
        label="Normal",
        summary="QuietWard is monitoring normally and has no active urgent findings.",
        reasons=("The evidence chain is valid and the latest monitoring cycle is current.",),
        recommended_action="No immediate action is needed. Continue normal monitoring.",
        active_critical=0,
        active_high=0,
        active_medium=0,
        evaluated_at=timestamp,
    )
