from pathlib import Path

from typer.testing import CliRunner

from aecontrol.cli import app


def test_cli_regression_then_fixed_flow(tmp_path: Path) -> None:
    runner = CliRunner()
    baseline = tmp_path / "baseline.json"
    regressed = tmp_path / "regressed.json"
    fixed = tmp_path / "fixed.json"
    regressed_comparison = tmp_path / "regressed-comparison.json"
    fixed_comparison = tmp_path / "fixed-comparison.json"
    regressed_html = tmp_path / "regressed.html"

    assert runner.invoke(app, ["agents", "versions"]).exit_code == 0
    assert (
        runner.invoke(
            app, ["datasets", "validate", "examples/datasets/coding_repair.jsonl"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app,
            [
                "run",
                "--suite",
                "examples/suites/coding_repair.yaml",
                "--agent-version",
                "baseline",
                "--output",
                str(baseline),
            ],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app,
            [
                "run",
                "--suite",
                "examples/suites/coding_repair.yaml",
                "--agent-version",
                "candidate_regressed",
                "--output",
                str(regressed),
            ],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app,
            [
                "compare",
                "--baseline",
                str(baseline),
                "--candidate",
                str(regressed),
                "--output",
                str(regressed_comparison),
            ],
        ).exit_code
        == 0
    )
    blocked = runner.invoke(
        app,
        [
            "gate",
            "--comparison",
            str(regressed_comparison),
            "--policy",
            "examples/policies/coding_repair_gate.yaml",
        ],
    )
    assert blocked.exit_code == 1
    assert "BLOCK" in blocked.output
    assert (
        runner.invoke(
            app,
            [
                "report",
                "--comparison",
                str(regressed_comparison),
                "--policy",
                "examples/policies/coding_repair_gate.yaml",
                "--baseline-run",
                str(baseline),
                "--candidate-run",
                str(regressed),
                "--output",
                str(regressed_html),
            ],
        ).exit_code
        == 0
    )
    html = regressed_html.read_text()
    assert "AgentEval Control Plane Report" in html
    assert "Regression Evidence" in html
    assert "SEC-01" in html
    assert "Candidate Patch" in html
    assert (
        runner.invoke(
            app,
            [
                "run",
                "--suite",
                "examples/suites/coding_repair.yaml",
                "--agent-version",
                "candidate_fixed",
                "--output",
                str(fixed),
            ],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app,
            [
                "compare",
                "--baseline",
                str(baseline),
                "--candidate",
                str(fixed),
                "--output",
                str(fixed_comparison),
            ],
        ).exit_code
        == 0
    )
    passed = runner.invoke(
        app,
        [
            "gate",
            "--comparison",
            str(fixed_comparison),
            "--policy",
            "examples/policies/coding_repair_gate.yaml",
        ],
    )
    assert passed.exit_code == 0
    assert "PASS" in passed.output
