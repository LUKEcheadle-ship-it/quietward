from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs" / "V05_DETECTION_REGRESSION_MATRIX.md"


def test_v05_detection_matrix_covers_detection_privacy_and_false_positive_cases() -> None:
    text = MATRIX.read_text(encoding="utf-8")
    for case_id in (
        "AUTH-01",
        "AUTH-02",
        "PROC-03",
        "PROC-04",
        "IMPACT-01",
        "IMPACT-05",
        "EVADE-01",
        "EVADE-02",
        "CHAIN-01",
        "CHAIN-05",
        "CHAIN-08",
        "PRIV-01",
        "SAFE-01",
    ):
        assert f"| {case_id} |" in text

    lower = text.lower()
    assert "review priority only" in lower
    assert "a test file existing is not a pass" in lower
    assert "actions_executed == 0" in lower
    assert "multiple phases and cross-subject evidence" in lower


def test_explicitly_mapped_v05_regression_files_exist() -> None:
    text = MATRIX.read_text(encoding="utf-8")
    names = set(re.findall(r"`(test_[a-z0-9_]+\.py)`", text))
    assert names
    missing = [name for name in sorted(names) if not (ROOT / "tests" / name).exists()]
    assert missing == []
