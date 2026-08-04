from __future__ import annotations

import argparse
import json
from pathlib import Path

from quietward.models import TrainingRow, evaluate_priority_model, train_priority_model


def load_rows(path: Path) -> list[TrainingRow]:
    rows: list[TrainingRow] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        raw = json.loads(line)
        if not isinstance(raw, dict) or not isinstance(raw.get("features"), dict):
            raise ValueError(f"{path}:{line_number}: invalid training row")
        rows.append(
            TrainingRow(
                {str(key): float(value) for key, value in raw["features"].items()},
                int(raw["label"]),
            )
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    rows = load_rows(args.dataset)
    model = train_priority_model(rows)
    model.save(args.output)
    print(json.dumps(evaluate_priority_model(model, rows), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
