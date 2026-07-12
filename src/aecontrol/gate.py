from __future__ import annotations

from pathlib import Path

import yaml

from aecontrol.models import (
    GateFinding,
    GateOutcome,
    QualityGateDecision,
    QualityGatePolicy,
    RunComparison,
)


def load_policy(path: Path) -> QualityGatePolicy:
    return QualityGatePolicy.model_validate(yaml.safe_load(path.read_text()))


def evaluate_gate(comparison: RunComparison, policy: QualityGatePolicy) -> QualityGateDecision:
    findings: list[GateFinding] = []
    minimum = policy.defaults.get("minimum_paired_cases", 0)
    if comparison.paired_cases < minimum:
        findings.append(
            GateFinding(
                scope="run",
                metric="paired_cases",
                outcome=GateOutcome.INCONCLUSIVE,
                observed_delta=None,
                threshold=float(minimum),
                message=f"only {comparison.paired_cases} paired cases",
            )
        )
    hidden_rule = policy.metrics.get("hidden_test_success")
    if hidden_rule and hidden_rule.maximum_absolute_drop is not None:
        threshold = -hidden_rule.maximum_absolute_drop
        if comparison.aggregate_pass_rate_delta < threshold:
            findings.append(
                GateFinding(
                    scope="run",
                    metric="hidden_test_success",
                    outcome=GateOutcome.BLOCK
                    if hidden_rule.severity == "blocking"
                    else GateOutcome.WARN,
                    observed_delta=comparison.aggregate_pass_rate_delta,
                    threshold=threshold,
                    message="aggregate hidden-test success dropped beyond threshold",
                )
            )
    forbidden_rule = policy.metrics.get("forbidden_modification_rate")
    if forbidden_rule and forbidden_rule.maximum_absolute_increase is not None:
        observed = comparison.metric_deltas.get("forbidden_modification_rate")
        if observed is None:
            findings.append(
                GateFinding(
                    scope="run",
                    metric="forbidden_modification_rate",
                    outcome=GateOutcome.INCONCLUSIVE,
                    observed_delta=None,
                    threshold=forbidden_rule.maximum_absolute_increase,
                    message="required forbidden modification metric is missing",
                )
            )
        elif observed > forbidden_rule.maximum_absolute_increase:
            findings.append(
                GateFinding(
                    scope="run",
                    metric="forbidden_modification_rate",
                    outcome=GateOutcome.BLOCK
                    if forbidden_rule.severity == "blocking"
                    else GateOutcome.WARN,
                    observed_delta=observed,
                    threshold=forbidden_rule.maximum_absolute_increase,
                    message="forbidden modification rate increased beyond threshold",
                )
            )
    for slice_name, rules in policy.slices.items():
        slice_row = next(
            (row for row in comparison.slice_comparisons if row.slice == slice_name), None
        )
        if slice_row is None:
            findings.append(
                GateFinding(
                    scope=f"slice:{slice_name}",
                    metric="hidden_test_success",
                    outcome=GateOutcome.INCONCLUSIVE,
                    observed_delta=None,
                    threshold=None,
                    message="required slice missing from comparison",
                )
            )
            continue
        rule = rules.get("hidden_test_success")
        if rule and rule.maximum_absolute_drop is not None:
            threshold = -rule.maximum_absolute_drop
            if slice_row.pass_rate_delta < threshold:
                findings.append(
                    GateFinding(
                        scope=f"slice:{slice_name}",
                        metric="hidden_test_success",
                        outcome=GateOutcome.BLOCK
                        if rule.severity == "blocking"
                        else GateOutcome.WARN,
                        observed_delta=slice_row.pass_rate_delta,
                        threshold=threshold,
                        message=f"{slice_name} hidden-test success dropped beyond threshold",
                    )
                )
    if any(finding.outcome == GateOutcome.BLOCK for finding in findings):
        outcome = GateOutcome.BLOCK
    elif any(finding.outcome == GateOutcome.INCONCLUSIVE for finding in findings):
        outcome = GateOutcome.INCONCLUSIVE
    elif any(finding.outcome == GateOutcome.WARN for finding in findings):
        outcome = GateOutcome.WARN
    else:
        outcome = GateOutcome.PASS
    return QualityGateDecision(
        outcome=outcome, findings=findings, regressed_cases=comparison.regressed_cases
    )
