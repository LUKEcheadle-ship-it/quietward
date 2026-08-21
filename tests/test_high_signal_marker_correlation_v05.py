from __future__ import annotations

from datetime import datetime, timedelta, timezone

from quietward.contracts import EventKind, SecurityEvent, Severity
from quietward.correlation import IncidentCorrelator
from quietward.scoring import DeterministicRiskScorer


NOW = datetime(2026, 8, 21, 18, 0, tzinfo=timezone.utc)


def _event(
    event_id: str,
    kind: EventKind,
    subject: str,
    *,
    seconds: int = 0,
    markers: list[str] | None = None,
    attributes: dict | None = None,
) -> SecurityEvent:
    attrs = dict(attributes or {})
    if markers is not None:
        attrs["suspicious_markers"] = markers
    return SecurityEvent(
        event_id=event_id,
        observed_at=NOW + timedelta(seconds=seconds),
        host_id="host-marker-correlation",
        source="test",
        kind=kind,
        subject=subject,
        attributes=attrs,
        confidence=0.95,
    )


def _chains(events: list[SecurityEvent]):
    scorer = DeterministicRiskScorer()
    findings = IncidentCorrelator().correlate(
        events,
        [scorer.score(event) for event in events],
    )
    return [item for item in findings if item.finding_id.startswith("qwf-chain-")]


def test_reverse_shell_marker_can_anchor_two_phase_cross_subject_chain() -> None:
    events = [
        _event(
            "evt-shell",
            EventKind.PROCESS_START,
            "proc:reverse-shell",
            markers=["reverse_shell"],
        ),
        _event(
            "evt-persistence",
            EventKind.PERSISTENCE_CHANGE,
            "task:startup",
            seconds=90,
            attributes={"persistence_indicator": True},
        ),
    ]
    chains = _chains(events)
    assert len(chains) == 1
    assert chains[0].severity in {Severity.HIGH, Severity.CRITICAL}
    assert any(
        reason == "attack_chain_high_signal_markers=reverse_shell"
        for reason in chains[0].reasons
    )


def test_ransomware_recovery_inhibition_can_anchor_impact_plus_file_chain() -> None:
    events = [
        _event(
            "evt-impact",
            EventKind.PROCESS_START,
            "proc:vssadmin",
            markers=["ransomware_recovery_inhibition"],
        ),
        _event(
            "evt-file",
            EventKind.SENSITIVE_FILE_CHANGE,
            "/etc/security-sensitive-placeholder",
            seconds=60,
            attributes={"baseline_deviation": 1.0},
        ),
    ]
    chains = _chains(events)
    assert len(chains) == 1
    assert any(
        "ransomware_recovery_inhibition" in reason
        for reason in chains[0].reasons
    )


def test_event_log_clearing_plus_identity_attack_can_form_two_phase_chain() -> None:
    events = [
        _event(
            "evt-auth",
            EventKind.AUTH_FAILURE,
            "auth:source:user",
            attributes={"failed_count": 20},
        ),
        _event(
            "evt-clear",
            EventKind.PROCESS_START,
            "proc:wevtutil",
            seconds=120,
            markers=["event_log_clearing"],
        ),
    ]
    chains = _chains(events)
    assert len(chains) == 1
    assert any("event_log_clearing" in reason for reason in chains[0].reasons)


def test_generic_low_signal_process_marker_does_not_unlock_two_phase_chain() -> None:
    events = [
        _event(
            "evt-process",
            EventKind.PROCESS_START,
            "proc:temp-tool",
            markers=["user_writable_executable"],
            attributes={"baseline_deviation": 1.0},
        ),
        _event(
            "evt-network",
            EventKind.OUTBOUND_CONNECTION,
            "connection:other-process",
            seconds=60,
            attributes={
                "external_destination": True,
                "process_name": "unrelated.exe",
            },
        ),
    ]
    assert _chains(events) == []


def test_high_signal_marker_still_requires_cross_subject_and_second_phase() -> None:
    one_event = [
        _event(
            "evt-one",
            EventKind.PROCESS_START,
            "proc:one",
            markers=["reverse_shell"],
        )
    ]
    assert _chains(one_event) == []

    same_subject = [
        _event(
            "evt-one",
            EventKind.PROCESS_START,
            "same-subject",
            markers=["reverse_shell"],
        ),
        _event(
            "evt-two",
            EventKind.PERSISTENCE_CHANGE,
            "same-subject",
            seconds=30,
            attributes={"persistence_indicator": True},
        ),
    ]
    assert _chains(same_subject) == []
