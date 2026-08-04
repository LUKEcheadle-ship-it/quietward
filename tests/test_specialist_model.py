from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from quietward.contracts import EventKind, SecurityEvent
from quietward.models import (
    HybridRiskScorer,
    LinearPriorityModel,
    TrainingRow,
    evaluate_priority_model,
    event_features,
    train_priority_model,
)
from quietward.scoring import DeterministicRiskScorer


class SpecialistModelTests(unittest.TestCase):
    def rows(self) -> list[TrainingRow]:
        return [TrainingRow({"kind_process": 1.0, "confidence": 1.0}, 0) for _ in range(4)] + [
            TrainingRow(
                {
                    "kind_malware": 1.0,
                    "authoritative_detection": 1.0,
                    "confidence": 1.0,
                },
                1,
            )
            for _ in range(4)
        ]

    def test_training_produces_real_compact_model(self) -> None:
        model = train_priority_model(self.rows(), epochs=300)
        metrics = evaluate_priority_model(model, self.rows())
        self.assertGreaterEqual(metrics["accuracy"], 0.9)
        self.assertLess(len(json.dumps(model.to_dict())), 10000)
        self.assertFalse(model.to_dict()["may_execute_actions"])

    def test_model_round_trip(self) -> None:
        model = train_priority_model(self.rows(), epochs=100)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "model.json"
            model.save(path)
            self.assertEqual(model.to_dict(), LinearPriorityModel.load(path).to_dict())

    def test_authoritative_detection_cannot_be_downgraded(self) -> None:
        model = LinearPriorityModel("test", "1", bias=-100, weights={})
        event = SecurityEvent(
            "event",
            datetime.now(timezone.utc),
            "host",
            "clamav",
            EventKind.MALWARE_SIGNATURE,
            "/tmp/bad",
            attributes={"authoritative_scanner_detection": True},
        )
        baseline = DeterministicRiskScorer().score(event)
        hybrid = HybridRiskScorer(model).score(event)
        self.assertGreaterEqual(hybrid.score, baseline.score)
        self.assertIn("tiny_model_rule=authoritative_floor", hybrid.reasons)

    def test_feature_extractor_omits_raw_values(self) -> None:
        event = SecurityEvent(
            "event",
            datetime.now(timezone.utc),
            "host",
            "test",
            EventKind.AUTH_FAILURE,
            "auth:hash",
            attributes={"failed_count": 16, "raw_log_message_persisted": False},
        )
        features = event_features(event)
        self.assertGreater(features["failed_count_log"], 0)
        self.assertNotIn("raw_log_message", features)


if __name__ == "__main__":
    unittest.main()
