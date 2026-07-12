from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import ValidationError

from aecontrol.models import Dataset, DatasetCase, DatasetSlice, ValidationIssue, ValidationReport


def load_jsonl_dataset(path: Path) -> Dataset:
    raw = path.read_bytes()
    cases: list[DatasetCase] = []
    for line_number, line in enumerate(raw.decode().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            cases.append(DatasetCase.model_validate_json(line))
        except ValidationError as exc:
            msg = f"invalid case on line {line_number}: {exc}"
            raise ValueError(msg) from exc
    version = "sha256:" + hashlib.sha256(raw).hexdigest()
    slices = [
        DatasetSlice(name=name, case_ids=[case.case_id for case in cases if case.slice == name])
        for name in sorted({case.slice for case in cases})
    ]
    return Dataset(name=path.stem, version=version, cases=cases, slices=slices)


def validate_jsonl_dataset(path: Path) -> ValidationReport:
    issues: list[ValidationIssue] = []
    seen: set[str] = set()
    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        return ValidationReport(
            valid=False,
            issues=[ValidationIssue(location=str(path), message=str(exc))],
        )
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            case = DatasetCase.model_validate(payload)
        except (json.JSONDecodeError, ValidationError) as exc:
            issues.append(ValidationIssue(location=f"line {line_number}", message=str(exc)))
            continue
        if case.case_id in seen:
            issues.append(
                ValidationIssue(
                    location=f"line {line_number}", message=f"duplicate case_id {case.case_id}"
                )
            )
        seen.add(case.case_id)
        for file_path in [*case.expected_modified_files, *case.forbidden_modified_files]:
            if Path(file_path).is_absolute() or ".." in Path(file_path).parts:
                issues.append(
                    ValidationIssue(
                        location=f"line {line_number}",
                        message=f"unsafe file path in expectations: {file_path}",
                    )
                )
    return ValidationReport(valid=not issues, issues=issues)
