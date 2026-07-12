from pathlib import Path

import pytest

from aecontrol.engine import EvaluationEngine, load_suite


@pytest.mark.asyncio
async def test_runtime_contract_returns_required_execution_fields() -> None:
    run = await EvaluationEngine().run(
        load_suite(Path("examples/suites/coding_repair.yaml")), "baseline"
    )
    first = run.case_results[0].output

    assert first.trajectory.steps
    assert first.patch
    assert "app.py" in first.modified_files
    assert first.public_test_output == "ok"
    assert first.hidden_test_output == "ok"


@pytest.mark.asyncio
async def test_evaluator_contract_names_are_unique() -> None:
    run = await EvaluationEngine().run(
        load_suite(Path("examples/suites/coding_repair.yaml")), "baseline"
    )
    names = [result.name for result in run.case_results[0].evaluator_results]

    assert len(names) == len(set(names))
