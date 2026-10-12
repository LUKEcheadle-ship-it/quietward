import importlib.util
from pathlib import Path
import sys
import pytest
from quietward.models import TrainingRow

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from release_metadata import release_metadata
from train_priority_model import validate_evaluation_split
from detection_gallery import build_gallery


def test_current_metadata_is_consistent_and_mismatch_is_rejected(tmp_path):
    assert release_metadata(ROOT) == ("0.6.0a1", "0.6.0-alpha.1")
    (tmp_path / "src/quietward").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text('[project]\nname="quietward"\nversion="0.7.0a1"\n')
    (tmp_path / "src/quietward/__init__.py").write_text('__version__ = "0.6.0a1"')
    with pytest.raises(ValueError, match="disagree"):
        release_metadata(tmp_path)


def test_evaluation_rejects_overlap_including_implicit_zero_features():
    train = [TrainingRow({"confidence": .9}, 0)]
    with pytest.raises(ValueError, match="overlap"):
        validate_evaluation_split(train, [TrainingRow({"confidence": .9, "kind_process": 0.0}, 1), TrainingRow({"confidence": .7}, 0)])
    validate_evaluation_split(train, [TrainingRow({"confidence": .8}, 1), TrainingRow({"confidence": .7}, 0)])


def test_gallery_is_synthetic_and_never_gains_execution_authority():
    result = build_gallery()
    assert result['actions_executed'] == 0 and result['host_scan'] is False
    assert len(result['cases']) == 8
    assert all('reasons' in row['deterministic'] for row in result['cases'])
