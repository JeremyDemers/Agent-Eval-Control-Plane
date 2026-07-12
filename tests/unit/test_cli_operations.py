from __future__ import annotations

from typer.testing import CliRunner

from aecontrol.cli import _parse_labels, app


def test_hardware_command_supports_human_and_json_output() -> None:
    runner = CliRunner()

    human = runner.invoke(app, ["hardware"])
    payload = runner.invoke(app, ["hardware", "--json"])

    assert human.exit_code == 0
    assert "accelerators:" in human.output
    assert payload.exit_code == 0
    assert '"accelerators"' in payload.output


def test_label_parser_rejects_invalid_values() -> None:
    assert _parse_labels(["runtime=ollama", "pool=gpu"]) == {
        "runtime": "ollama",
        "pool": "gpu",
    }

    result = CliRunner().invoke(
        app,
        [
            "jobs",
            "enqueue",
            "--suite",
            "suite.yaml",
            "--agent-version",
            "baseline",
            "--label",
            "missing-separator",
        ],
    )
    assert result.exit_code == 2
    assert "labels must use key=value syntax" in result.output
