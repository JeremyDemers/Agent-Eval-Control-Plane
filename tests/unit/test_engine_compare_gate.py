from pathlib import Path

import pytest

from aecontrol.compare import compare_runs
from aecontrol.engine import EvaluationEngine, load_suite
from aecontrol.gate import evaluate_gate, load_policy
from aecontrol.models import GateOutcome


@pytest.mark.asyncio
async def test_regressed_candidate_is_blocked() -> None:
    engine = EvaluationEngine()
    suite = load_suite(Path("examples/suites/coding_repair.yaml"))
    baseline = await engine.run(suite, "baseline")
    regressed = await engine.run(suite, "candidate_regressed")

    comparison = compare_runs(baseline, regressed)
    decision = evaluate_gate(
        comparison, load_policy(Path("examples/policies/coding_repair_gate.yaml"))
    )

    assert comparison.paired_cases == 24
    assert comparison.aggregate_pass_rate_delta == pytest.approx(-2 / 24)
    assert comparison.metric_deltas["hidden_test_success"] == pytest.approx(-2 / 24)
    assert comparison.metric_deltas["forbidden_modification_rate"] == 0
    assert comparison.regressed_cases == ["SEC-01", "SEC-04"]
    assert decision.outcome == GateOutcome.BLOCK


@pytest.mark.asyncio
async def test_fixed_candidate_passes() -> None:
    engine = EvaluationEngine()
    suite = load_suite(Path("examples/suites/coding_repair.yaml"))
    baseline = await engine.run(suite, "baseline")
    fixed = await engine.run(suite, "candidate_fixed")

    comparison = compare_runs(baseline, fixed)
    decision = evaluate_gate(
        comparison, load_policy(Path("examples/policies/coding_repair_gate.yaml"))
    )

    assert comparison.regressed_cases == []
    assert comparison.aggregate_pass_rate_delta == 0
    assert comparison.metric_deltas["forbidden_modification_rate"] == 0
    assert decision.outcome == GateOutcome.PASS
