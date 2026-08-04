from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from ..contracts import EventAssessment, EventKind, SecurityEvent
from ..scoring import DeterministicRiskScorer, severity_for_score


FEATURE_NAMES = (
    "confidence", "kind_malware", "kind_yara", "kind_container_escape", "kind_sensitive_file",
    "kind_executable", "kind_privilege", "kind_auth_failure", "kind_new_port", "kind_outbound",
    "kind_vulnerability", "kind_process", "known_bad_hash", "unsigned_executable", "external_destination",
    "privileged_context", "persistence_indicator", "failed_count_log", "cvss_scaled", "baseline_deviation",
    "suspicious_marker_count", "authoritative_detection",
)

_KIND_FEATURE = {
    EventKind.MALWARE_SIGNATURE: "kind_malware", EventKind.YARA_MATCH: "kind_yara",
    EventKind.CONTAINER_ESCAPE_INDICATOR: "kind_container_escape", EventKind.SENSITIVE_FILE_CHANGE: "kind_sensitive_file",
    EventKind.EXECUTABLE_CREATED: "kind_executable", EventKind.PRIVILEGE_ESCALATION: "kind_privilege",
    EventKind.AUTH_FAILURE: "kind_auth_failure", EventKind.NEW_LISTENING_PORT: "kind_new_port",
    EventKind.OUTBOUND_CONNECTION: "kind_outbound", EventKind.PACKAGE_VULNERABILITY: "kind_vulnerability",
    EventKind.PROCESS_START: "kind_process",
}


def event_features(event: SecurityEvent) -> dict[str, float]:
    values = {name: 0.0 for name in FEATURE_NAMES}
    values["confidence"] = float(event.confidence)
    kind_feature = _KIND_FEATURE.get(event.kind)
    if kind_feature:
        values[kind_feature] = 1.0
    attributes = event.attributes
    for name in ("known_bad_hash", "unsigned_executable", "external_destination", "privileged_context", "persistence_indicator"):
        values[name] = 1.0 if bool(attributes.get(name)) else 0.0
    failed_count = max(0, int(attributes.get("failed_count") or 0))
    values["failed_count_log"] = min(1.0, math.log2(failed_count + 1.0) / 6.0)
    values["cvss_scaled"] = min(1.0, max(0.0, float(attributes.get("cvss") or 0.0)) / 10.0)
    values["baseline_deviation"] = min(1.0, max(0.0, float(attributes.get("baseline_deviation") or 0.0)))
    markers = attributes.get("suspicious_markers") or []
    values["suspicious_marker_count"] = min(1.0, len(markers) / 4.0) if isinstance(markers, (list, tuple)) else 0.0
    values["authoritative_detection"] = 1.0 if (bool(attributes.get("authoritative_scanner_detection")) or bool(attributes.get("authoritative_rule_match")) or event.kind in {EventKind.MALWARE_SIGNATURE, EventKind.YARA_MATCH}) else 0.0
    return values


@dataclass(frozen=True, slots=True)
class LinearPriorityModel:
    model_id: str
    version: str
    bias: float
    weights: dict[str, float]
    threshold: float = 0.5
    training_scope: str = "bootstrap"

    def __post_init__(self) -> None:
        unknown = sorted(set(self.weights) - set(FEATURE_NAMES))
        if unknown:
            raise ValueError(f"unknown model features: {unknown}")
        if not 0.0 < self.threshold < 1.0:
            raise ValueError("threshold must be between 0 and 1")

    def probability(self, event: SecurityEvent) -> float:
        features = event_features(event)
        logit = self.bias + sum(self.weights.get(name, 0.0) * features[name] for name in FEATURE_NAMES)
        if logit >= 0:
            return 1.0 / (1.0 + math.exp(-logit))
        exp_value = math.exp(logit)
        return exp_value / (1.0 + exp_value)

    def to_dict(self) -> dict[str, Any]:
        return {"model_id": self.model_id, "version": self.version, "model_type": "logistic_priority_tiny", "bias": self.bias, "weights": {name: self.weights.get(name, 0.0) for name in FEATURE_NAMES}, "threshold": self.threshold, "feature_names": list(FEATURE_NAMES), "training_scope": self.training_scope, "may_override_authoritative_scanner": False, "may_execute_actions": False}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "LinearPriorityModel":
        if value.get("model_type") != "logistic_priority_tiny":
            raise ValueError("unsupported model type")
        if value.get("may_override_authoritative_scanner") not in (None, False):
            raise ValueError("model may not override authoritative scanners")
        if value.get("may_execute_actions") not in (None, False):
            raise ValueError("model may not execute actions")
        raw_weights = value.get("weights")
        if not isinstance(raw_weights, dict):
            raise ValueError("weights must be an object")
        return cls(model_id=str(value.get("model_id") or ""), version=str(value.get("version") or ""), bias=float(value.get("bias") or 0.0), weights={str(key): float(weight) for key, weight in raw_weights.items()}, threshold=float(value.get("threshold", 0.5)), training_scope=str(value.get("training_scope") or "unknown"))

    @classmethod
    def load(cls, path: Path) -> "LinearPriorityModel":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("model artifact must be a JSON object")
        return cls.from_dict(raw)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


@dataclass(frozen=True, slots=True)
class TrainingRow:
    features: dict[str, float]
    label: int


def train_priority_model(rows: Iterable[TrainingRow], *, epochs: int = 1_000, learning_rate: float = 0.12, l2: float = 0.002) -> LinearPriorityModel:
    data = list(rows)
    if len(data) < 8:
        raise ValueError("at least 8 training rows are required")
    if {row.label for row in data} != {0, 1}:
        raise ValueError("training rows must contain both labels")
    weights = {name: 0.0 for name in FEATURE_NAMES}
    bias = 0.0
    for _ in range(epochs):
        grad = {name: 0.0 for name in FEATURE_NAMES}
        bias_grad = 0.0
        for row in data:
            logit = bias + sum(weights[name] * float(row.features.get(name, 0.0)) for name in FEATURE_NAMES)
            probability = 1.0 / (1.0 + math.exp(-max(-40.0, min(40.0, logit))))
            error = probability - row.label
            bias_grad += error
            for name in FEATURE_NAMES:
                grad[name] += error * float(row.features.get(name, 0.0))
        scale = 1.0 / len(data)
        bias -= learning_rate * bias_grad * scale
        for name in FEATURE_NAMES:
            weights[name] -= learning_rate * (grad[name] * scale + l2 * weights[name])
    return LinearPriorityModel(model_id="quietward_priority_tiny_v1", version="1.0.0-bootstrap", bias=round(bias, 8), weights={name: round(value, 8) for name, value in weights.items()}, threshold=0.5, training_scope="synthetic_bootstrap_not_target_qualified")


def evaluate_priority_model(model: LinearPriorityModel, rows: Iterable[TrainingRow]) -> dict[str, float | int]:
    tp = fp = tn = fn = 0
    for row in rows:
        logit = model.bias + sum(model.weights.get(name, 0.0) * row.features.get(name, 0.0) for name in FEATURE_NAMES)
        prediction = int((1.0 / (1.0 + math.exp(-max(-40.0, min(40.0, logit))))) >= model.threshold)
        if prediction == 1 and row.label == 1: tp += 1
        elif prediction == 1: fp += 1
        elif row.label == 0: tn += 1
        else: fn += 1
    total = tp + fp + tn + fn
    return {"rows": total, "true_positive": tp, "false_positive": fp, "true_negative": tn, "false_negative": fn, "accuracy": (tp + tn) / total if total else 0.0, "precision": tp / (tp + fp) if tp + fp else 0.0, "recall": tp / (tp + fn) if tp + fn else 0.0}


class HybridRiskScorer:
    """Blends a tiny model with deterministic scoring without weakening scanner evidence."""

    def __init__(self, model: LinearPriorityModel, deterministic: DeterministicRiskScorer | None = None) -> None:
        self.model = model
        self.deterministic = deterministic or DeterministicRiskScorer()

    def score(self, event: SecurityEvent) -> EventAssessment:
        baseline = self.deterministic.score(event)
        probability = self.model.probability(event)
        model_score = probability * 100.0
        authoritative = event.kind in {EventKind.MALWARE_SIGNATURE, EventKind.YARA_MATCH} or bool(event.attributes.get("authoritative_scanner_detection") or event.attributes.get("authoritative_rule_match"))
        if authoritative:
            combined, rule = max(baseline.score, model_score), "authoritative_floor"
        else:
            combined, rule = 0.8 * baseline.score + 0.2 * model_score, "bounded_20_percent_blend"
        combined = min(100.0, max(0.0, combined))
        return EventAssessment(event_id=event.event_id, score=combined, severity=severity_for_score(combined), reasons=(*baseline.reasons, f"tiny_model_probability={probability:.4f}", f"tiny_model_rule={rule}"))
