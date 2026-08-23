from __future__ import annotations

from datetime import datetime, timezone

from quietward.contracts import EventKind, SecurityEvent
from quietward.service import _bypasses_suppression


def _event(*, kind: EventKind = EventKind.PROCESS_START, markers=(), spray=False):
    return SecurityEvent(
        event_id="suppression-safety-event",
        observed_at=datetime.now(timezone.utc),
        host_id="host-test",
        source="test",
        kind=kind,
        subject="process:test",
        attributes={
            "suspicious_markers": list(markers),
            "credential_spray_candidate": spray,
        },
        confidence=1.0,
    )


def test_high_confidence_behavior_cannot_be_hidden_by_prior_suppression() -> None:
    for marker in (
        "reverse_shell",
        "credential_dumping",
        "credential_theft",
        "process_injection",
        "document_spawned_interpreter",
        "web_server_spawned_suspicious_shell",
        "ransomware_recovery_inhibition",
        "event_log_clearing",
        "dangerous_container_config",
        "docker_socket_mount",
        "host_root_mount",
    ):
        assert _bypasses_suppression(_event(markers=(marker,))) is True


def test_credential_spray_candidate_bypasses_suppression() -> None:
    assert _bypasses_suppression(
        _event(kind=EventKind.AUTH_FAILURE, markers=("credential_spray",), spray=True)
    ) is True


def test_low_specificity_process_context_can_still_be_suppressed() -> None:
    assert _bypasses_suppression(
        _event(markers=("volatile_directory_executable",))
    ) is False


def test_existing_unsuppressible_evidence_kinds_remain_protected() -> None:
    for kind in (
        EventKind.MALWARE_SIGNATURE,
        EventKind.YARA_MATCH,
        EventKind.SELF_INTEGRITY_CHANGE,
        EventKind.EVIDENCE_INTEGRITY_FAILURE,
    ):
        assert _bypasses_suppression(_event(kind=kind)) is True
