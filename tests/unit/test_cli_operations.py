from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from aecontrol.cli import _parse_labels, app
from aecontrol.guardrails import GuardrailEvidence, GuardrailsConfig
from aecontrol.models import Accelerator, EvaluationJob
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


def test_gpu_load_options_are_forwarded_and_rendered(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}
    job = EvaluationJob(
        suite_path="suite.yaml",
        agent_version="baseline",
        required_accelerator=Accelerator.CUDA,
        minimum_gpu_memory_available_mb=4096,
        maximum_gpu_utilization_percent=25,
    )

    class Store:
        def __init__(self, _database_url: str) -> None:
            pass

        def enqueue_job(self, *_args, **kwargs):  # type: ignore[no-untyped-def]
            captured.update(kwargs)
            return job

        def list_jobs(self, **_kwargs):  # type: ignore[no-untyped-def]
            return [job]

    monkeypatch.setattr("aecontrol.cli.ArtifactStore", Store)
    runner = CliRunner()
    queued = runner.invoke(
        app,
        [
            "jobs",
            "enqueue",
            "--suite",
            "suite.yaml",
            "--agent-version",
            "baseline",
            "--accelerator",
            "cuda",
            "--minimum-gpu-memory-available-mb",
            "4096",
            "--maximum-gpu-utilization-percent",
            "25",
        ],
    )
    listed = runner.invoke(app, ["jobs", "list"])

    assert queued.exit_code == 0
    assert captured["minimum_gpu_memory_available_mb"] == 4096
    assert captured["maximum_gpu_utilization_percent"] == 25
    assert "gpu_free>=4096MiB utilization<=25%" in listed.output
    assert "gpu_memory" not in listed.output


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


def test_nim_cli_commands(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    async def models(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        return [CompatibleModel(id="meta/llama-test")]

    monkeypatch.setenv("NIM_BASE_URL", "http://nim.local/v1")
    monkeypatch.setattr("aecontrol.cli.NIMClient.models", models)
    runner = CliRunner()
    doctor = runner.invoke(app, ["nim", "doctor"])
    payload = runner.invoke(app, ["nim", "models", "--json"])
    assert doctor.exit_code == 0
    assert "NVIDIA NIM" in doctor.output
    assert '"id": "meta/llama-test"' in payload.output


def test_guardrails_cli_commands(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    async def configs(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        return [GuardrailsConfig(id="content_safety")]

    async def check(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        return GuardrailEvidence(
            config_id="content_safety",
            model="meta/llama",
            submitted_text="answer",
            response_text="answer",
            passed_through=True,
        )

    monkeypatch.setattr("aecontrol.cli.GuardrailsClient.configs", configs)
    monkeypatch.setattr("aecontrol.cli.GuardrailsClient.check", check)
    runner = CliRunner()
    listed = runner.invoke(app, ["guardrails", "configs"])
    checked = runner.invoke(
        app,
        [
            "guardrails",
            "check",
            "--model",
            "meta/llama",
            "--config",
            "content_safety",
            "--input",
            "question",
            "--output",
            "answer",
        ],
    )
    assert listed.exit_code == 0
    assert "content_safety" in listed.output
    assert checked.exit_code == 0
    assert '"passed_through": true' in checked.output


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
