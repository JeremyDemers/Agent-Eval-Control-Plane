from __future__ import annotations

import base64
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from aecontrol.cli import _parse_labels, app
from aecontrol.guardrails import (
    GuardrailConfigActivation,
    GuardrailConfigVersion,
    GuardrailEfficacyMetrics,
    GuardrailEfficacyReport,
    GuardrailEvidence,
    GuardrailsConfig,
)
from aecontrol.models import (
    Accelerator,
    EvaluationJob,
    GpuCapacityForecast,
    GpuDurationEstimate,
    GpuQueueJobForecast,
)
from aecontrol.openai_compatible import CompatibleModel


def test_doctor_reports_sanitized_telemetry_destination(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv(
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "https://collector-user:collector-secret@traces.example:4318",
    )

    result = CliRunner().invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "telemetry: otlp/http host=traces.example" in result.output
    assert "collector-user" not in result.output
    assert "collector-secret" not in result.output


def test_doctor_reports_hardened_podman_configuration(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("AECONTROL_SANDBOX_BACKEND", "podman")
    monkeypatch.setenv(
        "AECONTROL_SANDBOX_IMAGE",
        "registry.example/aecontrol-sandbox@sha256:" + "a" * 64,
    )
    monkeypatch.setenv("AECONTROL_SANDBOX_REQUIRE_DIGEST", "true")
    monkeypatch.setenv("AECONTROL_SANDBOX_APPARMOR_PROFILE", "aecontrol-sandbox")

    result = CliRunner().invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "sandbox image: digest-pinned (pinning required)" in result.output
    assert "seccomp=runtime-default" in result.output
    assert "apparmor=aecontrol-sandbox" in result.output


def test_one_shot_worker_always_shuts_down_telemetry(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    events: list[str] = []

    class Worker:
        def __init__(self, *_args, **_kwargs) -> None:  # type: ignore[no-untyped-def]
            pass

        async def run_once(self):  # type: ignore[no-untyped-def]
            return None

    monkeypatch.setattr(
        "aecontrol.cli.configure_telemetry_from_environment", lambda: events.append("start")
    )
    monkeypatch.setattr("aecontrol.cli.shutdown_telemetry", lambda: events.append("shutdown"))
    monkeypatch.setattr("aecontrol.cli.ArtifactStore", lambda _database_url: object())
    monkeypatch.setattr("aecontrol.cli.EvaluationWorker", Worker)
    monkeypatch.setattr("aecontrol.cli.detect_worker_capabilities", lambda _labels: object())

    result = CliRunner().invoke(app, ["worker", "--once"])

    assert result.exit_code == 0
    assert "queue empty" in result.output
    assert events == ["start", "shutdown"]


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
        required_mig_profile="3g.40gb",
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
            "--mig-profile",
            "3g.40gb",
        ],
    )
    listed = runner.invoke(app, ["jobs", "list"])

    assert queued.exit_code == 0
    assert captured["minimum_gpu_memory_available_mb"] == 4096
    assert captured["maximum_gpu_utilization_percent"] == 25
    assert captured["required_mig_profile"] == "3g.40gb"
    assert "gpu_free>=4096MiB utilization<=25% mig_profile=3g.40gb" in listed.output
    assert "gpu_memory" not in listed.output


def test_gpu_capacity_command_supports_human_and_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    job = EvaluationJob(
        suite_path="suite.yaml",
        agent_version="nim/model",
        required_accelerator=Accelerator.CUDA,
    )
    forecast = GpuCapacityForecast(
        observed_at=job.created_at,
        active_worker_window_seconds=120,
        active_cuda_workers=1,
        active_gpus=1,
        memory_telemetry_gpus=1,
        utilization_telemetry_gpus=1,
        total_gpu_memory_mb=24576,
        available_gpu_memory_mb=20000,
        average_gpu_utilization_percent=10,
        queued_cuda_jobs=1,
        first_wave_jobs=1,
        deferred_jobs=0,
        blocked_jobs=0,
        minimum_clearance_waves=1,
        estimated_clearance_seconds=45,
        estimate_confidence="low",
        duration_estimates=[
            GpuDurationEstimate(
                mig_profile=None, sample_count=3, average_seconds=30, p90_seconds=45
            )
        ],
        jobs=[
            GpuQueueJobForecast(
                job_id=job.job_id,
                agent_version=job.agent_version,
                priority=job.priority,
                state="first_wave",
                matching_workers=1,
                assigned_worker_id="gpu-worker",
            )
        ],
    )

    class Store:
        def __init__(self, _database_url: str) -> None:
            pass

        def gpu_capacity_forecast(self) -> GpuCapacityForecast:
            return forecast

    monkeypatch.setattr("aecontrol.cli.ArtifactStore", Store)
    human = CliRunner().invoke(app, ["jobs", "capacity"])
    payload = CliRunner().invoke(app, ["jobs", "capacity", "--json"])

    assert human.exit_code == 0
    assert "first_wave=1" in human.output
    assert "worker=gpu-worker" in human.output
    assert "historical ETA: 45.0s confidence=low" in human.output
    assert "history all-cuda: n=3 average=30.0s p90=45.0s" in human.output
    assert payload.exit_code == 0
    assert '"minimum_clearance_waves": 1' in payload.output


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


def test_guardrails_cli_manages_version_activation_and_history(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    version = GuardrailConfigVersion(
        config_id="content_safety",
        version="2026.07.1",
        bundle_sha256="a" * 64,
        created_by="local-trust",
        active=True,
    )
    activation = GuardrailConfigActivation(
        config_id=version.config_id,
        version=version.version,
        bundle_sha256=version.bundle_sha256,
        activated_by="local-trust",
    )
    efficacy = GuardrailEfficacyReport(
        window_start=datetime(2026, 7, 1, tzinfo=UTC),
        window_end=datetime(2026, 7, 31, tzinfo=UTC),
        total_checks=5,
        labeled_checks=4,
        versions=[
            GuardrailEfficacyMetrics(
                config_id="content_safety",
                config_version="2026.07.1",
                sample_count=5,
                labeled_count=4,
                pass_through_count=3,
                intervention_count=2,
                true_positives=1,
                false_positives=1,
                true_negatives=2,
                false_negatives=0,
                label_coverage=0.8,
                intervention_rate=0.4,
                accuracy=0.75,
                precision=0.5,
                recall=1,
                false_positive_rate=1 / 3,
            )
        ],
    )

    class Store:
        def __init__(self, _database_url: str) -> None:
            pass

        def list_guardrail_config_versions(self):  # type: ignore[no-untyped-def]
            return [version]

        def register_guardrail_config_version(self, *_args, **_kwargs):  # type: ignore[no-untyped-def]
            return version

        def activate_guardrail_config(self, *_args, **_kwargs):  # type: ignore[no-untyped-def]
            return activation

        def list_guardrail_config_activations(self, *_args, **_kwargs):  # type: ignore[no-untyped-def]
            return [activation]

        def guardrail_efficacy_report(self, **_kwargs):  # type: ignore[no-untyped-def]
            return efficacy

    async def configs(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        return [GuardrailsConfig(id="content_safety")]

    monkeypatch.setattr("aecontrol.cli.ArtifactStore", Store)
    monkeypatch.setattr("aecontrol.cli.GuardrailsClient.configs", configs)
    runner = CliRunner()

    listed = runner.invoke(app, ["guardrails", "versions"])
    registered = runner.invoke(
        app,
        [
            "guardrails",
            "register",
            "--config",
            "content_safety",
            "--version",
            "2026.07.1",
            "--bundle-sha256",
            "a" * 64,
        ],
    )
    activated = runner.invoke(
        app,
        [
            "guardrails",
            "activate",
            "--config",
            "content_safety",
            "--version",
            "2026.07.1",
        ],
    )
    history = runner.invoke(app, ["guardrails", "activations", "--config", "content_safety"])
    measured = runner.invoke(
        app, ["guardrails", "efficacy", "--config", "content_safety", "--days", "30"]
    )

    assert listed.exit_code == 0
    assert "content_safety@2026.07.1 active" in listed.output
    assert registered.exit_code == 0
    assert "registered content_safety@2026.07.1" in registered.output
    assert activated.exit_code == 0
    assert "activated content_safety@2026.07.1" in activated.output
    assert history.exit_code == 0
    assert "by=local-trust" in history.output
    assert measured.exit_code == 0
    assert "checks=5 labeled=4 window=30d" in measured.output
    assert "accuracy=75.0%" in measured.output
    assert "false-positive-rate=33.3%" in measured.output


def test_guardrails_cli_digests_configuration_bundle(tmp_path: Path) -> None:
    config = tmp_path / "content_safety"
    config.mkdir()
    (config / "config.yml").write_text("rails: {}\n")

    result = CliRunner().invoke(app, ["guardrails", "digest", str(config)])

    assert result.exit_code == 0
    assert len(result.output.strip()) == 64


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


def test_store_cli_generates_a_256_bit_signing_key() -> None:
    result = CliRunner().invoke(app, ["store", "generate-signing-key"])

    assert result.exit_code == 0
    assert len(base64.b64decode(result.output.strip(), validate=True)) == 32
