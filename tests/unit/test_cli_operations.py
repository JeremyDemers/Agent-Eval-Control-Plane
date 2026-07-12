from __future__ import annotations

from pathlib import Path

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


def test_auth_cli_hashes_and_validates_configuration(tmp_path: Path) -> None:
    runner = CliRunner()
    hashed = runner.invoke(app, ["auth", "hash-key", "--secret", "test-secret"])
    assert hashed.exit_code == 0
    digest = hashed.output.strip()
    assert len(digest) == 64

    config = tmp_path / "auth.yaml"
    config.write_text(
        f"keys:\n  - key_id: ci\n    secret_sha256: {digest}\n    scopes: [read, write]\n"
    )
    validated = runner.invoke(app, ["auth", "validate", str(config)])
    assert validated.exit_code == 0
    assert "valid" in validated.output
    assert "keys=1" in validated.output

    empty = runner.invoke(app, ["auth", "hash-key", "--secret", ""])
    assert empty.exit_code == 2
    assert "must not be empty" in empty.output
