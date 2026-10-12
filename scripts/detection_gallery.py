#!/usr/bin/env python3
"""Synthetic scoring gallery and deterministic-vs-hybrid comparison. No host IO."""
from __future__ import annotations
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from quietward.contracts import EventKind, SecurityEvent
from quietward.pipeline import SentinelPipeline
from quietward.models import LinearPriorityModel, HybridRiskScorer


def build_gallery() -> dict:
    fixtures = [
        ("Routine process", EventKind.PROCESS_START, {}, False),
        ("Ordinary file change", EventKind.FILE_CHANGE, {}, False),
        ("Single authentication failure", EventKind.AUTH_FAILURE, {"failed_count": 1}, False),
        ("Loopback listener", EventKind.NEW_LISTENING_PORT, {"external_bind": False}, False),
        ("Synthetic scanner detection", EventKind.MALWARE_SIGNATURE, {"known_bad_hash": True}, True),
        ("Reverse-shell marker", EventKind.PROCESS_START, {"suspicious_markers": ["reverse_shell"]}, True),
        ("Credential spray", EventKind.AUTH_FAILURE, {"failed_count": 32, "distinct_accounts": 8, "suspicious_markers": ["credential_spray"]}, True),
        ("Evidence integrity failure", EventKind.EVIDENCE_INTEGRITY_FAILURE, {}, True),
    ]
    model = LinearPriorityModel.load(ROOT / "models/quietward_priority_tiny_v1.json")
    rows = []
    for index, (name, kind, attributes, expected) in enumerate(fixtures):
        event = SecurityEvent(f"gallery-{index}", datetime(2026, 9, 14, tzinfo=timezone.utc),
                              "synthetic-host", "synthetic-gallery", kind, f"synthetic-subject-{index}",
                              {**attributes, "synthetic": True}, confidence=1.0)
        row = {"case": name, "event_kind": kind.value, "expected_high_priority": expected}
        for label, scorer in (("deterministic", None), ("hybrid", HybridRiskScorer(model))):
            report = SentinelPipeline(scorer=scorer).analyze([event])
            assert report.actions_executed == 0
            assert not any(p.executable_in_current_mode for p in report.action_proposals)
            assessment = report.assessments[0]
            row[label] = {"score": round(assessment.score, 3), "severity": assessment.severity.value,
                          "reasons": list(assessment.reasons), "high_priority": assessment.score >= 65}
        rows.append(row)
    metrics = {}
    for label in ("deterministic", "hybrid"):
        tp = sum(r["expected_high_priority"] and r[label]["high_priority"] for r in rows)
        fp = sum(not r["expected_high_priority"] and r[label]["high_priority"] for r in rows)
        fn = sum(r["expected_high_priority"] and not r[label]["high_priority"] for r in rows)
        metrics[label] = {"true_positive": tp, "false_positive": fp, "false_negative": fn,
                          "precision": tp/(tp+fp) if tp+fp else None, "recall": tp/(tp+fn) if tp+fn else None}
    return {"scope": "Eight synthetic examples of supported rules, not independent real-world detection accuracy.",
            "threshold": 65, "actions_executed": 0, "host_scan": False, "cases": rows, "metrics": metrics}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = build_gallery()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("# Synthetic detection gallery\n")
        print(result["scope"] + "\n")
        print("| Example | Deterministic score | Hybrid score | Expected high priority |")
        print("| --- | --- | --- | --- |")
        for row in result["cases"]:
            print(f"| {row['case']} | {row['deterministic']['score']} | {row['hybrid']['score']} | {row['expected_high_priority']} |")
        print("\nThreshold: 65. No host scan or action execution. Use --json for reasons and synthetic confusion counts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
