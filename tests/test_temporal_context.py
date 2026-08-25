from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from quietward.contextual_pipeline import ContextualPipeline
from quietward.contracts import EventKind, SecurityEvent
from quietward.pipeline import SentinelPipeline
from quietward.temporal_context import TemporalContextWindow


NOW = datetime(2026, 8, 8, 16, 0, tzinfo=timezone.utc)


def process_event(event_id: str, *, name: str = "suspicious-agent.exe", pid: int | None = 4242):
    attributes = {"process_name": name}
    if pid is not None:
        attributes["pid"] = pid
    return SecurityEvent(
        event_id,
        NOW,
        "host-a",
        "windows_process_snapshot",
        EventKind.PROCESS_START,
        f"process:{event_id}",
        attributes,
    )


def listener_event(
    event_id: str,
    observed_at: datetime,
    *,
    name: str = "suspicious-agent.exe",
    pid: int | None = 4242,
):
    attributes = {
        "owner_command_name": name,
        "external_bind": True,
    }
    if pid is not None:
        attributes["owner_pid"] = pid
    return SecurityEvent(
        event_id,
        observed_at,
        "host-a",
        "windows_socket_snapshot",
        EventKind.NEW_LISTENING_PORT,
        "tcp://0.0.0.0:4444",
        attributes,
    )


class TemporalContextTests(unittest.TestCase):
    def test_prior_durable_pid_context_strengthens_next_cycle_and_is_traceable(self) -> None:
        pipeline = ContextualPipeline(SentinelPipeline())
        prior = process_event("process-1")
        pipeline.analyze([prior])
        pipeline.commit_pending()

        current = listener_event("listener-1", NOW + timedelta(minutes=1))
        report = pipeline.analyze([current])
        self.assertEqual(len(report.findings), 1)
        finding = report.findings[0]
        self.assertIn("process-1", finding.evidence_event_ids)
        self.assertIn("listener-1", finding.evidence_event_ids)
        self.assertTrue(
            any("temporal_actor_context" in reason for reason in finding.reasons)
        )
        self.assertTrue(
            any("temporal_context_evidence_ids=1" == reason for reason in finding.reasons)
        )
        self.assertGreaterEqual(finding.score, 40.0)
        self.assertEqual(pipeline.state()["pending_events"], 1)
        pipeline.commit_pending()
        self.assertEqual(pipeline.state()["retained_events"], 2)

    def test_pid_reuse_with_different_identity_does_not_link(self) -> None:
        window = TemporalContextWindow()
        window.observe(
            [process_event("old-owner", name="old-agent.exe", pid=4242)]
        )
        current = listener_event(
            "reused-pid",
            NOW + timedelta(minutes=1),
            name="different-agent.exe",
            pid=4242,
        )
        enriched = window.enrich([current])[0]
        self.assertNotIn("temporal_context_count", enriched.attributes)

    def test_same_name_with_different_known_pid_does_not_link_instances(self) -> None:
        window = TemporalContextWindow()
        window.observe(
            [process_event("first-instance", name="agent.exe", pid=4242)]
        )
        current = listener_event(
            "second-instance",
            NOW + timedelta(minutes=1),
            name="agent.exe",
            pid=5000,
        )
        enriched = window.enrich([current])[0]
        self.assertNotIn("temporal_context_count", enriched.attributes)

    def test_distinctive_name_can_link_when_one_side_lacks_pid(self) -> None:
        window = TemporalContextWindow()
        window.observe(
            [process_event("name-only-prior", name="agent.exe", pid=None)]
        )
        current = listener_event(
            "named-listener",
            NOW + timedelta(minutes=1),
            name="agent.exe",
            pid=5000,
        )
        enriched = window.enrich([current])[0]
        self.assertEqual(enriched.attributes["temporal_context_count"], 1)
        self.assertTrue(enriched.attributes["temporal_context_actor_match"])

    def test_generic_runtime_name_does_not_link_across_subjects(self) -> None:
        window = TemporalContextWindow()
        window.observe([process_event("python-1", name="python", pid=None)])
        current = listener_event(
            "python-listener",
            NOW + timedelta(minutes=1),
            name="python",
            pid=None,
        )
        enriched = window.enrich([current])[0]
        self.assertNotIn("temporal_context_count", enriched.attributes)

    def test_context_expires_after_bounded_window(self) -> None:
        window = TemporalContextWindow(window_seconds=300.0)
        window.observe([process_event("process-old")])
        current = listener_event(
            "listener-late",
            NOW + timedelta(seconds=301),
        )
        enriched = window.enrich([current])[0]
        self.assertNotIn("temporal_context_count", enriched.attributes)
        self.assertEqual(window.state()["retained_events"], 0)

    def test_discarded_cycle_does_not_enter_future_context(self) -> None:
        pipeline = ContextualPipeline(SentinelPipeline())
        prior = process_event("undurable-process")
        pipeline.analyze([prior])
        self.assertEqual(pipeline.state()["pending_events"], 1)
        pipeline.discard_pending()
        self.assertEqual(pipeline.state()["retained_events"], 0)

        current = listener_event(
            "listener-after-failure",
            NOW + timedelta(minutes=1),
        )
        report = pipeline.analyze([current])
        self.assertEqual(len(report.findings), 1)
        self.assertNotIn("undurable-process", report.findings[0].evidence_event_ids)

    def test_second_analysis_requires_commit_or_discard(self) -> None:
        pipeline = ContextualPipeline(SentinelPipeline())
        pipeline.analyze([process_event("pending")])
        with self.assertRaisesRegex(RuntimeError, "uncommitted"):
            pipeline.analyze(
                [listener_event("second", NOW + timedelta(minutes=1))]
            )


if __name__ == "__main__":
    unittest.main()
