from pathlib import Path

from aecontrol.datasets import load_jsonl_dataset, validate_jsonl_dataset
from aecontrol.models import DatasetCase


def test_dataset_loads_24_cases() -> None:
    dataset = load_jsonl_dataset(Path("examples/datasets/coding_repair.jsonl"))

    assert len(dataset.cases) == 24
    assert dataset.version.startswith("sha256:")
    assert {item.name for item in dataset.slices} == {
        "async_python",
        "general_python",
        "security_sensitive",
        "typing_required",
    }


def test_dataset_validation_reports_success() -> None:
    report = validate_jsonl_dataset(Path("examples/datasets/coding_repair.jsonl"))

    assert report.valid
    assert report.issues == []


def test_dataset_case_rejects_empty_id() -> None:
    try:
        DatasetCase(case_id="", title="bad", slice="general_python", bug_kind="divide")
    except ValueError as exc:
        assert "value must not be empty" in str(exc)
    else:
        raise AssertionError("expected validation failure")
