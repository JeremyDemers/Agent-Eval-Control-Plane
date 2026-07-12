from __future__ import annotations

from html import escape

from aecontrol.models import CaseResult, EvaluationRun, QualityGateDecision, RunComparison


def render_html(
    comparison: RunComparison,
    decision: QualityGateDecision,
    baseline: EvaluationRun | None = None,
    candidate: EvaluationRun | None = None,
) -> str:
    candidate_by_id = (
        {result.case.case_id: result for result in candidate.case_results} if candidate else {}
    )
    rows = "\n".join(
        "<tr>"
        f"<td>{escape(case.case_id)}</td>"
        f"<td>{escape(case.slice)}</td>"
        f"<td>{escape(case.classification)}</td>"
        f"<td>{escape(case.explanation)}</td>"
        "</tr>"
        for case in comparison.case_comparisons
    )
    slices = "\n".join(
        "<tr>"
        f"<td>{escape(row.slice)}</td>"
        f"<td>{row.baseline_pass_rate:.2%}</td>"
        f"<td>{row.candidate_pass_rate:.2%}</td>"
        f"<td>{row.pass_rate_delta:.2%}</td>"
        "</tr>"
        for row in comparison.slice_comparisons
    )
    findings = (
        "\n".join(
            f"<li><strong>{escape(finding.outcome)}</strong> {escape(finding.scope)} "
            f"{escape(finding.metric)}: {escape(finding.message)}</li>"
            for finding in decision.findings
        )
        or "<li>No blocking findings.</li>"
    )
    evidence = "\n".join(
        _render_evidence(case_id, candidate_by_id[case_id])
        for case_id in comparison.regressed_cases
        if case_id in candidate_by_id
    )
    if not evidence:
        evidence = "<p>No candidate run artifact was provided for patch-level evidence.</p>"
    baseline_name = escape(baseline.agent_version) if baseline else "baseline"
    candidate_name = escape(candidate.agent_version) if candidate else "candidate"
    sample_label = "limited sample" if comparison.limited_evidence else "standard sample"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AgentEval Control Plane Report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #202124; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #d0d7de; padding: 0.5rem; text-align: left; }}
    th {{ background: #f6f8fa; }}
    pre {{ background: #0f172a; color: #e2e8f0; padding: 1rem; overflow-x: auto; border-radius: 6px; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    .summary {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; margin: 1rem 0; }}
    .metric {{ border: 1px solid #d0d7de; border-radius: 6px; padding: 1rem; }}
    .outcome {{ display: inline-block; padding: 0.4rem 0.7rem; border-radius: 6px; background: #111827; color: white; }}
  </style>
</head>
<body>
  <h1>AgentEval Control Plane Report</h1>
  <p class="outcome">{escape(decision.outcome)}</p>
  <div class="summary">
    <div class="metric"><strong>Baseline</strong><br>{baseline_name}</div>
    <div class="metric"><strong>Candidate</strong><br>{candidate_name}</div>
    <div class="metric"><strong>Aggregate Delta</strong><br>{comparison.aggregate_pass_rate_delta:.2%}</div>
  </div>
  <p>Paired cases: {comparison.paired_cases}. Evidence: {sample_label}.</p>
  <h2>Gate Findings</h2>
  <ul>{findings}</ul>
  <h2>Slice Breakdown</h2>
  <table><thead><tr><th>Slice</th><th>Baseline</th><th>Candidate</th><th>Delta</th></tr></thead><tbody>{slices}</tbody></table>
  <h2>Case Comparisons</h2>
  <table><thead><tr><th>Case</th><th>Slice</th><th>Class</th><th>Explanation</th></tr></thead><tbody>{rows}</tbody></table>
  <h2>Regression Evidence</h2>
  {evidence}
</body>
</html>"""


def _render_evidence(case_id: str, result: CaseResult) -> str:
    output = result.output
    tool_names = [
        str(step.data.get("name")) for step in output.trajectory.steps if step.kind == "tool_call"
    ]
    return (
        f"<section><h3>{escape(case_id)}: {escape(result.case.title)}</h3>"
        f"<p>Slice: {escape(result.case.slice)}. Tools: {escape(', '.join(tool_names))}.</p>"
        "<h4>Candidate Patch</h4>"
        f"<pre><code>{escape(output.patch)}</code></pre>"
        "<h4>Hidden Test Output</h4>"
        f"<pre><code>{escape(output.hidden_test_output)}</code></pre>"
        "</section>"
    )
