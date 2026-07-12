from uuid import uuid4

from hypothesis import given
from hypothesis import strategies as st

from aecontrol.compare import compare_runs
from aecontrol.models import (
    AgentOutput,
    AgentTrajectory,
    CaseResult,
    DatasetCase,
    EvaluationResult,
    EvaluationRun,
    ExecutionStatus,
    utc_now,
)


def make_run(flags: list[bool], version: str) -> EvaluationRun:
    cases = []
    for index, flag in enumerate(flags):
        case = DatasetCase(
            case_id=f"CASE-{index:03d}",
            title="case",
            slice="general_python",
            bug_kind="divide",
        )
        output = AgentOutput(
            trajectory=AgentTrajectory(),
            patch="",
            modified_files=["app.py"],
            public_test_output="ok",
            hidden_test_output="ok" if flag else "fail",
            duration_seconds=0.01,
            status=ExecutionStatus.PASSED if flag else ExecutionStatus.FAILED,
        )
        cases.append(
            CaseResult(
                case=case,
                agent_version=version,
                status=output.status,
                started_at=utc_now(),
                completed_at=utc_now(),
                output=output,
                evaluator_results=[
                    EvaluationResult(
                        name="hidden_test_success",
                        passed=flag,
                        score=float(flag),
                        explanation="property",
                    )
                ],
            )
        )
    return EvaluationRun(
        run_id=uuid4(),
        suite_name="property",
        dataset_name="property",
        dataset_version="sha256:test",
        agent_version=version,
        started_at=utc_now(),
        completed_at=utc_now(),
        case_results=cases,
    )


@given(
    st.lists(st.booleans(), min_size=1, max_size=20),
    st.lists(st.booleans(), min_size=1, max_size=20),
)
def test_comparison_pair_count_never_exceeds_shorter_run(
    left: list[bool], right: list[bool]
) -> None:
    comparison = compare_runs(make_run(left, "left"), make_run(right, "right"))

    assert comparison.paired_cases == min(len(left), len(right))
    assert len(comparison.case_comparisons) == comparison.paired_cases
