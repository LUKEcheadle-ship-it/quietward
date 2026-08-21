from __future__ import annotations

from datetime import datetime, timedelta, timezone

from quietward.contracts import EventKind, SecurityEvent, Severity
from quietward.correlation import IncidentCorrelator
from quietward.scoring import DeterministicRiskScorer


NOW = datetime(2026, 8, 21, 15, 0, tzinfo=timezone.utc)


def _event(
    event_id: str,
    kind: EventKind,
    subject: str,
    *,
    seconds: int = 0,
    attributes: dict | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        observed_at=NOW + timedelta(seconds=seconds),
        host_id="host-corroboration",
        source="test",
        kind=kind,
        subject=subject,
        attributes=attributes or {},
        confidence=0.95,
    )


def _chains(events: list[SecurityEvent]):
    scorer = DeterministicRiskScorer()
    return [
        item
        for item in IncidentCorrelator().correlate(
            events,
            [scorer.score(event) for event in events],
        )
        if item.finding_id.startswith("qwf-chain-")
    ]


def test_suspicious_process_and_matching_public_connection_are_correlated() -> None:
    events = [
        _event(
            "evt-process",
            EventKind.PROCESS_START,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            attributes={
                "command_name": "powershell.exe",
                "suspicious_markers": ["reverse_shell"],
            },
        ),
        _event(
            "evt-network",
            EventKind.OUTBOUND_CONNECTION,
            "connection:public-destination-hash:4444",
            seconds=30,
            attributes={
                "process_name": "powershell.exe",
                "external_destination": True,
            },
        ),
    ]
    chains = _chains(events)
    assert len(chains) == 1
    assert chains[0].severity in {Severity.HIGH, Severity.CRITICAL}
    assert "process_network_corroboration=powershell.exe" in chains[0].reasons
    assert "process_network_corroboration_bonus=+12.0" in chains[0].reasons


def test_different_network_process_does_not_receive_corroboration() -> None:
    events = [
        _event(
            "evt-process",
            EventKind.PROCESS_START,
            "powershell.exe",
            attributes={
                "command_name": "powershell.exe",
                "suspicious_markers": ["reverse_shell"],
            },
        ),
        _event(
            "evt-network",
            EventKind.OUTBOUND_CONNECTION,
            "connection:public-destination-hash:443",
            seconds=30,
            attributes={
                "process_name": "chrome.exe",
                "external_destination": True,
            },
        ),
    ]
    assert _chains(events) == []


def test_matching_process_name_without_suspicious_marker_does_not_form_chain() -> None:
    events = [
        _event(
            "evt-process",
            EventKind.PROCESS_START,
            "powershell.exe",
            attributes={
                "command_name": "powershell.exe",
                "suspicious_markers": [],
            },
        ),
        _event(
            "evt-network",
            EventKind.OUTBOUND_CONNECTION,
            "connection:public-destination-hash:443",
            seconds=30,
            attributes={
                "process_name": "powershell.exe",
                "external_destination": True,
            },
        ),
    ]
    assert _chains(events) == []


def test_matching_suspicious_process_and_new_listener_are_correlated() -> None:
    events = [
        _event(
            "evt-process",
            EventKind.PROCESS_START,
            "/usr/bin/ncat",
            attributes={
                "command_name": "ncat",
                "suspicious_markers": ["network_listener_tool", "reverse_shell"],
            },
        ),
        _event(
            "evt-listener",
            EventKind.NEW_LISTENING_PORT,
            "tcp://*:4444",
            seconds=20,
            attributes={
                "process_name": "ncat",
                "external_bind": True,
                "port": 4444,
            },
        ),
    ]
    chains = _chains(events)
    assert len(chains) == 1
    assert "process_network_corroboration=ncat" in chains[0].reasons
