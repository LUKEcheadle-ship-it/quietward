from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

from .config import CollectorSettings


class CoverageState(StrEnum):
    COMPLETE = "complete"
    DEGRADED = "degraded"
    DISABLED = "disabled"
    NOT_DUE = "not_due"


@dataclass(frozen=True, slots=True)
class CoverageDomain:
    name: str
    state: CoverageState
    required_for_resolution: bool
    reason_code: str | None = None
    issue_count: int = 0

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("coverage domain name must not be empty")
        if self.issue_count < 0:
            raise ValueError("coverage issue_count must not be negative")
        if self.state == CoverageState.COMPLETE and self.issue_count:
            raise ValueError("complete coverage cannot report issues")

    @property
    def resolution_complete(self) -> bool:
        return not self.required_for_resolution or self.state == CoverageState.COMPLETE

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "state": self.state.value,
            "required_for_resolution": self.required_for_resolution,
            "resolution_complete": self.resolution_complete,
            "reason_code": self.reason_code,
            "issue_count": self.issue_count,
        }


@dataclass(frozen=True, slots=True)
class CoverageReport:
    domains: tuple[CoverageDomain, ...]

    @property
    def resolution_safe(self) -> bool:
        return all(domain.resolution_complete for domain in self.domains)

    @property
    def degraded_count(self) -> int:
        return sum(
            1
            for domain in self.domains
            if domain.state in {CoverageState.DEGRADED, CoverageState.NOT_DUE}
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "resolution_safe": self.resolution_safe,
            "degraded_count": self.degraded_count,
            "domains": [domain.to_dict() for domain in self.domains],
            "actions_executed": 0,
        }


def domain(
    name: str,
    *,
    enabled: bool,
    required_for_resolution: bool = True,
    issues: int = 0,
    reason_code: str = "collector_error",
) -> CoverageDomain:
    if not enabled:
        return CoverageDomain(
            name=name,
            state=CoverageState.DISABLED,
            required_for_resolution=False,
            reason_code="disabled_by_configuration",
        )
    if issues:
        return CoverageDomain(
            name=name,
            state=CoverageState.DEGRADED,
            required_for_resolution=required_for_resolution,
            reason_code=reason_code,
            issue_count=issues,
        )
    return CoverageDomain(
        name=name,
        state=CoverageState.COMPLETE,
        required_for_resolution=required_for_resolution,
    )


def not_due_domain(name: str) -> CoverageDomain:
    return CoverageDomain(
        name=name,
        state=CoverageState.NOT_DUE,
        required_for_resolution=True,
        reason_code="scheduled_not_due",
    )


def degraded_domain(
    name: str,
    *,
    reason_code: str,
    issue_count: int = 1,
    required_for_resolution: bool = True,
) -> CoverageDomain:
    return CoverageDomain(
        name=name,
        state=CoverageState.DEGRADED,
        required_for_resolution=required_for_resolution,
        reason_code=reason_code,
        issue_count=issue_count,
    )


def complete_domain(
    name: str,
    *,
    required_for_resolution: bool = True,
) -> CoverageDomain:
    return CoverageDomain(
        name=name,
        state=CoverageState.COMPLETE,
        required_for_resolution=required_for_resolution,
    )


def _matches(error: str, patterns: tuple[str, ...]) -> bool:
    lowered = error.casefold()
    return any(pattern in lowered for pattern in patterns)


def collector_coverage(
    settings: CollectorSettings,
    errors: Iterable[str],
    *,
    collector_version: str,
) -> tuple[CoverageDomain, ...]:
    error_values = tuple(str(error) for error in errors)
    consumed: set[int] = set()

    def issue_count(patterns: tuple[str, ...]) -> int:
        count = 0
        for index, error in enumerate(error_values):
            if _matches(error, patterns):
                consumed.add(index)
                count += 1
        return count

    domains = [
        domain(
            "processes",
            enabled=settings.include_processes,
            issues=issue_count(("process inventory", "process privacy identity")),
        ),
        domain(
            "listening_sockets",
            enabled=settings.include_listening_sockets,
            issues=issue_count(("listening socket inventory", "listener process attribution")),
        ),
        domain(
            "outbound_connections",
            enabled=settings.include_outbound_connections,
            issues=issue_count(("outbound connection inventory", "outbound privacy identity")),
        ),
        domain(
            "authentication",
            enabled=settings.include_auth_journal,
            issues=issue_count(("failed-logon event inventory", "authentication privacy identity", "authentication journal")),
        ),
        domain(
            "docker",
            enabled=settings.include_docker,
            issues=issue_count(("docker inventory", "docker inspect")),
        ),
        domain(
            "persistence",
            enabled=settings.include_persistence,
            issues=issue_count(("persistence",)),
        ),
        domain(
            "sensitive_files",
            enabled=bool(settings.sensitive_files),
            issues=issue_count(("file observation",)),
        ),
    ]

    is_windows = collector_version.casefold().startswith("windows")
    if is_windows:
        domains.append(
            domain(
                "microsoft_defender",
                enabled=True,
                required_for_resolution=False,
                issues=issue_count(("defender status",)),
                reason_code="optional_security_context_unavailable",
            )
        )

    unclassified = len(error_values) - len(consumed)
    if unclassified:
        domains.append(
            degraded_domain(
                "collector_other",
                reason_code="unclassified_collector_warning",
                issue_count=unclassified,
            )
        )
    return tuple(domains)


def report(domains: Iterable[CoverageDomain]) -> CoverageReport:
    return CoverageReport(tuple(domains))
