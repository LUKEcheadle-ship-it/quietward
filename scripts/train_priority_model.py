from __future__ import annotations

import argparse
import json
import math
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from quietward.models import TrainingRow, evaluate_priority_model, train_priority_model
from quietward.models.specialist import FEATURE_NAMES


def load_rows(path: Path) -> list[TrainingRow]:
    rows: list[TrainingRow] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        raw = json.loads(line)
        if not isinstance(raw, dict) or not isinstance(raw.get("features"), dict):
            raise ValueError(f"{path}:{line_number}: invalid training row")
        features = {str(key): float(value) for key, value in raw["features"].items()}
        if set(features) - set(FEATURE_NAMES) or not all(math.isfinite(v) for v in features.values()):
            raise ValueError(f"{path}:{line_number}: unknown or non-finite feature")
        if type(raw.get("label")) is not int or raw["label"] not in (0, 1):
            raise ValueError(f"{path}:{line_number}: label must be 0 or 1")
        rows.append(TrainingRow(features, raw["label"]))
    return rows


def validate_evaluation_split(training: list[TrainingRow], evaluation: list[TrainingRow]) -> None:
    if {row.label for row in evaluation} != {0, 1}:
        raise ValueError("evaluation data must contain both labels")
    def key(row):
        return tuple(row.features.get(name, 0.0) for name in FEATURE_NAMES)
    if {key(row) for row in training} & {key(row) for row in evaluation}:
        raise ValueError("training and evaluation feature vectors overlap")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--evaluation-dataset", type=Path, required=True,
                        help="Separate held-out JSONL; must not overlap training features")
    args = parser.parse_args()
    rows = load_rows(args.dataset)
    evaluation = load_rows(args.evaluation_dataset)
    validate_evaluation_split(rows, evaluation)
    if args.output.resolve() in {args.dataset.resolve(), args.evaluation_dataset.resolve()}:
        raise ValueError("model output must not overwrite a dataset")
    model = train_priority_model(rows)
    model.save(args.output)
    print(json.dumps({"training_rows": len(rows), "evaluation": evaluate_priority_model(model, evaluation),
                      "training_sha256": hashlib.sha256(args.dataset.read_bytes()).hexdigest(),
                      "evaluation_sha256": hashlib.sha256(args.evaluation_dataset.read_bytes()).hexdigest(),
                      "scope": "Held-out metrics on the supplied data; representativeness must be assessed separately."}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
