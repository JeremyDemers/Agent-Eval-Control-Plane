from __future__ import annotations

from typer.testing import CliRunner

from aecontrol.cli import _parse_labels, app
from aecontrol.openai_compatible import CompatibleModel


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


def test_openai_compatible_cli_commands(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    async def models(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        return [CompatibleModel(id="test-model")]

    monkeypatch.setattr("aecontrol.cli.OpenAICompatibleClient.models", models)
    runner = CliRunner()

    doctor = runner.invoke(app, ["openai", "doctor"])
    human = runner.invoke(app, ["openai", "models"])
    payload = runner.invoke(app, ["openai", "models", "--json"])

    assert doctor.exit_code == 0
    assert "healthy" in doctor.output
    assert "test-model" in human.output
    assert '"id": "test-model"' in payload.output
