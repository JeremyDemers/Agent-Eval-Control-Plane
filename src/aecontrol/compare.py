from __future__ import annotations

import random
from collections import defaultdict
from typing import Literal

from aecontrol.models import (
    CaseComparison,
    CaseResult,
    EvaluationRun,
    RunComparison,
    SliceComparison,
)

Classification = Literal["improved", "regressed", "unchanged_pass", "unchanged_fail"]


def compare_runs(baseline: EvaluationRun, candidate: EvaluationRun) -> RunComparison:
    baseline_by_id = {result.case.case_id: result for result in baseline.case_results}
    candidate_by_id = {result.case.case_id: result for result in candidate.case_results}
    paired_ids = sorted(set(baseline_by_id) & set(candidate_by_id))
    missing = sorted(set(baseline_by_id) ^ set(candidate_by_id))
    case_comparisons: list[CaseComparison] = []
    improved: list[str] = []
    regressed: list[str] = []
    unchanged_passes = 0
    unchanged_failures = 0
    deltas: list[int] = []
    for case_id in paired_ids:
        base_passed = baseline_by_id[case_id].hidden_success
        cand_passed = candidate_by_id[case_id].hidden_success
        deltas.append(int(cand_passed) - int(base_passed))
        if cand_passed and not base_passed:
            classification: Classification = "improved"
            improved.append(case_id)
        elif base_passed and not cand_passed:
            classification = "regressed"
            regressed.append(case_id)
        elif base_passed and cand_passed:
            classification = "unchanged_pass"
            unchanged_passes += 1
        else:
            classification = "unchanged_fail"
            unchanged_failures += 1
        case_comparisons.append(
            CaseComparison(
                case_id=case_id,
                slice=baseline_by_id[case_id].case.slice,
                baseline_passed=base_passed,
                candidate_passed=cand_passed,
                classification=classification,
                metric_deltas=_case_metric_deltas(
                    baseline_by_id[case_id], candidate_by_id[case_id]
                ),
                explanation=f"{baseline.agent_version}={base_passed}, {candidate.agent_version}={cand_passed}",
            )
        )
    aggregate_delta = sum(deltas) / len(deltas) if deltas else 0.0
    return RunComparison(
        baseline_run_id=baseline.run_id,
        candidate_run_id=candidate.run_id,
        paired_cases=len(paired_ids),
        missing_pairs=missing,
        aggregate_pass_rate_delta=aggregate_delta,
        metric_deltas=_run_metric_deltas(baseline, candidate),
        confidence_interval=_bootstrap_ci(deltas) if len(deltas) >= 10 else None,
        limited_evidence=len(deltas) < 30,
        improved_cases=improved,
        regressed_cases=regressed,
        unchanged_passes=unchanged_passes,
        unchanged_failures=unchanged_failures,
        slice_comparisons=_slice_comparisons(case_comparisons),
        case_comparisons=case_comparisons,
    )


def _slice_comparisons(cases: list[CaseComparison]) -> list[SliceComparison]:
    grouped: dict[str, list[CaseComparison]] = defaultdict(list)
    for case in cases:
        grouped[case.slice].append(case)
    output: list[SliceComparison] = []
    for name, rows in sorted(grouped.items()):
        baseline_rate = sum(row.baseline_passed for row in rows) / len(rows)
        candidate_rate = sum(row.candidate_passed for row in rows) / len(rows)
        output.append(
            SliceComparison(
                slice=name,
                paired_cases=len(rows),
                baseline_pass_rate=baseline_rate,
                candidate_pass_rate=candidate_rate,
                pass_rate_delta=candidate_rate - baseline_rate,
            )
        )
    return output


def _bootstrap_ci(deltas: list[int], samples: int = 500, seed: int = 7) -> tuple[float, float]:
    rng = random.Random(seed)
    means = []
    for _ in range(samples):
        sample = [rng.choice(deltas) for _ in deltas]
        means.append(sum(sample) / len(sample))
    means.sort()
    lower = means[int(samples * 0.025)]
    upper = means[int(samples * 0.975)]
    return (lower, upper)


def _case_metric_deltas(baseline: CaseResult, candidate: CaseResult) -> dict[str, float]:
    baseline_scores = {result.name: result.score for result in baseline.evaluator_results}
    candidate_scores = {result.name: result.score for result in candidate.evaluator_results}
    return {
        name: candidate_scores[name] - baseline_scores[name]
        for name in sorted(set(baseline_scores) & set(candidate_scores))
    }


def _run_metric_deltas(baseline: EvaluationRun, candidate: EvaluationRun) -> dict[str, float]:
    baseline_averages = _average_metric_scores(baseline)
    candidate_averages = _average_metric_scores(candidate)
    deltas = {
        name: candidate_averages[name] - baseline_averages[name]
        for name in sorted(set(baseline_averages) & set(candidate_averages))
    }
    deltas["forbidden_modification_rate"] = _forbidden_modification_rate(candidate) - (
        _forbidden_modification_rate(baseline)
    )
    return deltas


def _average_metric_scores(run: EvaluationRun) -> dict[str, float]:
    totals: dict[str, list[float]] = defaultdict(list)
    for case in run.case_results:
        for result in case.evaluator_results:
            totals[result.name].append(result.score)
    return {name: sum(values) / len(values) for name, values in totals.items() if values}


def _forbidden_modification_rate(run: EvaluationRun) -> float:
    if not run.case_results:
        return 0.0
    failures = 0
    for case in run.case_results:
        result = next(
            (
                evaluator_result
                for evaluator_result in case.evaluator_results
                if evaluator_result.name == "forbidden_file_modification"
            ),
            None,
        )
        if result is not None and not result.passed:
            failures += 1
    return failures / len(run.case_results)
