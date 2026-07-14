from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from typer.testing import CliRunner

from aecontrol.aws_kms import AWS_KMS_KEY_ARN_ENV
from aecontrol.bedrock import BedrockConfiguration, BedrockModel
from aecontrol.checkpoints import (
    FileCheckpointSink,
    LedgerCheckpointPayload,
    SignedLedgerCheckpoint,
)
from aecontrol.cli import _parse_labels, app
from aecontrol.fleet import (
    FleetQuotaSaturation,
    FleetResourceSnapshot,
    PlatformFleetReport,
    TenantFleetSummary,
)
from aecontrol.guardrails import (
    GuardrailConfigActivation,
    GuardrailConfigVersion,
    GuardrailEfficacyMetrics,
    GuardrailEfficacyReport,
    GuardrailEvidence,
    GuardrailsConfig,
)
from aecontrol.integrity import (
    ED25519,
    ED25519_PUBLIC_KEYS_ENV,
    SIGNING_ALGORITHM_ENV,
    SIGNING_KEY_ID_ENV,
    generate_ed25519_keypair,
)
from aecontrol.kubernetes_sandbox import (
    KUBERNETES_NAMESPACE_ENV,
    KUBERNETES_RUNTIME_CLASS_ENV,
    KUBERNETES_RUNTIME_HANDLER_ENV,
    SANDBOX_IMAGE_ENV,
)
from aecontrol.models import (
    Accelerator,
    EvaluationJob,
    GpuCapacityForecast,
    GpuDemandForecast,
    GpuDemandHour,
    GpuDurationEstimate,
    GpuQueueJobForecast,
)
from aecontrol.openai_compatible import CompatibleModel
from aecontrol.tenants import (
    TenantQuotaLimits,
    TenantQuotaRecord,
    TenantQuotaStatus,
    TenantQuotaUsage,
)
from aecontrol.vault import (
    VAULT_ADDR_ENV,
    VAULT_KEY_ENV,
    VAULT_KEY_VERSION_ENV,
    VAULT_TOKEN_ENV,
)


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


def test_bedrock_cli_reports_region_and_models_without_profile(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    model = BedrockModel(
        model_id="us.anthropic.claude-test-v1:0",
        model_name="Claude Test",
        provider_name="Anthropic",
        input_modalities=["TEXT"],
        output_modalities=["TEXT"],
        inference_types=["ON_DEMAND"],
        response_streaming_supported=True,
    )

    class Client:
        configuration = BedrockConfiguration("us-east-2", "secret-profile", 30)

        async def models(self):  # type: ignore[no-untyped-def]
            return [model]

    monkeypatch.setattr("aecontrol.cli.BedrockClient", Client)
    doctor = CliRunner().invoke(app, ["bedrock", "doctor"])
    assert doctor.exit_code == 0
    assert "region=us-east-2, text_models=1" in doctor.output
    assert "secret-profile" not in doctor.output

    models = CliRunner().invoke(app, ["bedrock", "models", "--json"])
    assert models.exit_code == 0
    assert '"model_id": "us.anthropic.claude-test-v1:0"' in models.output


def test_doctor_reports_sanitized_vault_transit_signer(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _, public_key = generate_ed25519_keypair()
    monkeypatch.setenv(SIGNING_KEY_ID_ENV, "vault-evidence-v4")
    monkeypatch.setenv(SIGNING_ALGORITHM_ENV, ED25519)
    monkeypatch.setenv(
        ED25519_PUBLIC_KEYS_ENV,
        json.dumps({"vault-evidence-v4": base64.b64encode(public_key).decode()}),
    )
    monkeypatch.setenv(VAULT_ADDR_ENV, "https://vault.internal.example")
    monkeypatch.setenv(VAULT_TOKEN_ENV, "hvs.must-not-appear")
    monkeypatch.setenv(VAULT_KEY_ENV, "sensitive-key-name")
    monkeypatch.setenv(VAULT_KEY_VERSION_ENV, "4")

    result = CliRunner().invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "artifact signing: vault-transit host=vault.internal.example" in result.output
    assert "mount=transit" in result.output
    assert "key_version=4" in result.output
    assert "hvs.must-not-appear" not in result.output
    assert "sensitive-key-name" not in result.output


def test_doctor_reports_sanitized_aws_kms_signer(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _, public_key = generate_ed25519_keypair()
    key_arn = "arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-1234567890ab"
    monkeypatch.setattr("boto3.client", lambda *_args, **_kwargs: object())
    monkeypatch.setenv(SIGNING_KEY_ID_ENV, "kms-evidence")
    monkeypatch.setenv(SIGNING_ALGORITHM_ENV, ED25519)
    monkeypatch.setenv(
        ED25519_PUBLIC_KEYS_ENV,
        json.dumps({"kms-evidence": base64.b64encode(public_key).decode()}),
    )
    monkeypatch.setenv(AWS_KMS_KEY_ARN_ENV, key_arn)

    result = CliRunner().invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "artifact signing: aws-kms region=us-east-2" in result.output
    assert "key_arn_sha256=" in result.output
    assert "123456789012" not in result.output
    assert "12345678-1234" not in result.output


def test_auth_federation_diagnostics_are_sanitized(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv(
        "AECONTROL_OIDC_ISSUER", "https://issuer-user:issuer-secret@identity.example/agents"
    )
    monkeypatch.setenv("AECONTROL_OIDC_AUDIENCE", "aecontrol-api,aecontrol-workers")
    monkeypatch.setenv("AECONTROL_OIDC_JWKS_URL", "https://identity.example/agents/jwks")

    invalid = CliRunner().invoke(app, ["auth", "federation"])
    assert invalid.exit_code != 0
    assert "must not include credentials" in invalid.output
    assert "issuer-secret" not in invalid.output

    monkeypatch.setenv("AECONTROL_OIDC_ISSUER", "https://identity.example/agents")
    valid = CliRunner().invoke(app, ["auth", "federation"])
    assert valid.exit_code == 0
    assert "identity federation: valid" in valid.output
    assert "issuer host: identity.example" in valid.output
    assert "JWKS host: identity.example" in valid.output
    assert "audiences: 2" in valid.output
    assert "aecontrol-api" not in valid.output


def test_tenant_quota_cli_sets_policy_and_reports_usage(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    stored = TenantQuotaRecord(
        tenant_id="research",
        max_queued_jobs=12,
        max_jobs_per_hour=60,
        max_running_jobs=4,
        max_running_cuda_jobs=2,
        updated_at=now,
        updated_by="portfolio-demo",
    )
    quota_status = TenantQuotaStatus(
        quota=stored,
        usage=TenantQuotaUsage(
            queued_jobs=3,
            active_running_jobs=2,
            active_running_cuda_jobs=1,
            jobs_submitted_last_hour=9,
            measured_at=now,
            submission_window_started_at=now - timedelta(hours=1),
        ),
    )
    observed = {}

    class Store:
        def __init__(self, _database_url: str) -> None:
            pass

        def set_tenant_quota(self, tenant_id, quota, *, updated_by):  # type: ignore[no-untyped-def]
            observed.update(tenant_id=tenant_id, quota=quota, updated_by=updated_by)
            return stored

        def tenant_quota_status(self):  # type: ignore[no-untyped-def]
            return quota_status

    monkeypatch.setattr("aecontrol.cli.ArtifactStore", Store)
    configured = CliRunner().invoke(
        app,
        [
            "tenant",
            "quota-set",
            "research",
            "--max-queued-jobs",
            "12",
            "--max-jobs-per-hour",
            "60",
            "--max-running-jobs",
            "4",
            "--max-running-cuda-jobs",
            "2",
            "--updated-by",
            "portfolio-demo",
        ],
    )
    assert configured.exit_code == 0
    assert "tenant quota updated: research" in configured.output
    assert observed["updated_by"] == "portfolio-demo"

    status = CliRunner().invoke(app, ["tenant", "quota-status"])
    assert status.exit_code == 0
    assert "queued=3/12 hourly=9/60 running=2/4 cuda=1/2" in status.output


def test_platform_fleet_cli_renders_human_and_json_reports(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    resources = FleetResourceSnapshot(
        queued_cpu_jobs=1,
        queued_cuda_jobs=2,
        active_running_cpu_jobs=0,
        active_running_cuda_jobs=1,
        jobs_submitted_last_hour=3,
        workers_observed=1,
        active_cpu_workers=1,
        active_cuda_workers=1,
        active_gpu_devices=4,
        oldest_queued_seconds=12,
    )
    report = PlatformFleetReport(
        observed_at=datetime.now(UTC),
        active_worker_window_seconds=120,
        totals=resources,
        tenants=[
            TenantFleetSummary(
                tenant_id="research",
                display_name="Research",
                status="active",
                quota=TenantQuotaLimits(max_queued_jobs=3),
                saturation=FleetQuotaSaturation(
                    queued_jobs=True,
                    jobs_per_hour=False,
                    running_jobs=False,
                    running_cuda_jobs=False,
                ),
                **resources.model_dump(),
            )
        ],
    )

    class Store:
        def __init__(self, _database_url: str) -> None:
            pass

        def platform_fleet_report(self, active_worker_window_seconds: int):  # type: ignore[no-untyped-def]
            assert active_worker_window_seconds == 120
            return report

    monkeypatch.setattr("aecontrol.cli.ArtifactStore", Store)
    human = CliRunner().invoke(app, ["platform", "fleet"])
    payload = CliRunner().invoke(app, ["platform", "fleet", "--json"])

    assert human.exit_code == 0
    assert "queued_cpu=1 queued_cuda=2" in human.output
    assert "research status=active queue=3 running=1 cuda_workers=1 gpus=4" in human.output
    assert payload.exit_code == 0
    assert json.loads(payload.output)["totals"]["active_gpu_devices"] == 4


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


def test_doctor_reports_pinned_kubernetes_runtimeclass_sandbox(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("AECONTROL_SANDBOX_BACKEND", "kubernetes-runtimeclass")
    monkeypatch.setenv(KUBERNETES_NAMESPACE_ENV, "isolated-evals")
    monkeypatch.setenv(KUBERNETES_RUNTIME_CLASS_ENV, "kata-qemu")
    monkeypatch.setenv(KUBERNETES_RUNTIME_HANDLER_ENV, "kata-qemu")
    monkeypatch.setenv(SANDBOX_IMAGE_ENV, "registry.example/python@sha256:" + "a" * 64)

    result = CliRunner().invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "sandbox: kubernetes-runtimeclass" in result.output
    assert "sandbox runtime: class=kata-qemu handler=kata-qemu" in result.output
    assert "sandbox image: digest-pinned namespace=isolated-evals" in result.output


def test_doctor_reports_bounded_database_pool(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("AECONTROL_DATABASE_POOL_MIN_SIZE", "2")
    monkeypatch.setenv("AECONTROL_DATABASE_POOL_MAX_SIZE", "8")
    monkeypatch.setenv("AECONTROL_DATABASE_POOL_TIMEOUT_SECONDS", "2.5")
    monkeypatch.setenv("AECONTROL_DATABASE_MIGRATION_LOCK_TIMEOUT_SECONDS", "15")

    result = CliRunner().invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "database: pooled min=2 max=8 timeout=2.5s" in result.output
    assert "database migration lock: 15s" in result.output
    assert "tenant: default" in result.output


def test_doctor_reports_sanitized_dcgm_destination(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv(
        "AECONTROL_DCGM_EXPORTER_URL",
        "https://metrics-user:metrics-secret@dcgm.example:9400/metrics",
    )
    monkeypatch.setenv("AECONTROL_DCGM_POD_NAME", "gpu-worker-1")

    result = CliRunner().invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "dcgm exporter: enabled host=dcgm.example timeout=1s pod=gpu-worker-1" in result.output
    assert "metrics-user" not in result.output
    assert "metrics-secret" not in result.output


def test_one_shot_worker_always_shuts_down_telemetry(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    events: list[str] = []

    class Store:
        def __init__(self, *_args, **_kwargs) -> None:  # type: ignore[no-untyped-def]
            pass

        def close(self) -> None:
            events.append("store-close")

    class Worker:
        def __init__(self, *_args, **kwargs) -> None:  # type: ignore[no-untyped-def]
            self.capability_provider = kwargs["capability_provider"]

        async def run_once(self):  # type: ignore[no-untyped-def]
            self.capability_provider()
            return None

    monkeypatch.setattr(
        "aecontrol.cli.configure_telemetry_from_environment", lambda: events.append("start")
    )
    monkeypatch.setattr("aecontrol.cli.shutdown_telemetry", lambda: events.append("shutdown"))
    monkeypatch.setattr("aecontrol.cli.ArtifactStore", Store)
    monkeypatch.setattr("aecontrol.cli.EvaluationWorker", Worker)
    monkeypatch.setattr(
        "aecontrol.cli.detect_worker_capabilities",
        lambda _labels: events.append("capabilities") or object(),
    )

    result = CliRunner().invoke(app, ["worker", "--once"])

    assert result.exit_code == 0
    assert "queue empty" in result.output
    assert events == ["start", "capabilities", "store-close", "shutdown"]


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


def test_gpu_demand_command_supports_human_and_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    observed_at = datetime(2026, 7, 13, 18, tzinfo=UTC)
    forecast = GpuDemandForecast(
        observed_at=observed_at,
        history_start=observed_at - timedelta(days=56),
        lookback_days=56,
        horizon_hours=24,
        historical_cuda_jobs=24,
        observed_history_hours=1344,
        current_queued_cuda_jobs=2,
        current_running_cuda_jobs=1,
        predicted_cuda_arrivals=3.5,
        average_cuda_duration_seconds=600,
        projected_gpu_seconds=3900,
        available_gpu_seconds=86400,
        projected_capacity_ratio=0.045139,
        active_cuda_workers=1,
        confidence="high",
        saturation="within_capacity",
        hours=[
            GpuDemandHour(
                hour_start=observed_at + timedelta(hours=1),
                historical_occurrences=8,
                historical_arrivals=12,
                predicted_arrivals=1.5,
            )
        ],
    )

    class Store:
        def __init__(self, _database_url: str) -> None:
            pass

        def gpu_demand_forecast(self) -> GpuDemandForecast:
            return forecast

    monkeypatch.setattr("aecontrol.cli.ArtifactStore", Store)
    human = CliRunner().invoke(app, ["jobs", "demand"])
    payload = CliRunner().invoke(app, ["jobs", "demand", "--json"])

    assert human.exit_code == 0
    assert "arrivals=3.50, queued=2, running=1" in human.output
    assert "capacity=4.5%" in human.output
    assert "state=within_capacity" in human.output
    assert "confidence=high" in human.output
    assert "history=12/8" in human.output
    assert payload.exit_code == 0
    assert '"predicted_cuda_arrivals": 3.5' in payload.output


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
    assert "tenants=1" in validated.output

    empty = runner.invoke(app, ["auth", "hash-key", "--secret", ""])
    assert empty.exit_code == 2
    assert "must not be empty" in empty.output


def test_store_cli_generates_a_256_bit_signing_key() -> None:
    result = CliRunner().invoke(app, ["store", "generate-signing-key"])

    assert result.exit_code == 0
    assert len(base64.b64decode(result.output.strip(), validate=True)) == 32

    asymmetric = CliRunner().invoke(
        app, ["store", "generate-signing-key", "--algorithm", "ed25519"]
    )
    assert asymmetric.exit_code == 0
    key_pair = json.loads(asymmetric.output)
    assert key_pair["algorithm"] == "ed25519"
    assert len(base64.b64decode(key_pair["private_key"], validate=True)) == 32
    assert len(base64.b64decode(key_pair["public_key"], validate=True)) == 32

    invalid = CliRunner().invoke(app, ["store", "generate-signing-key", "--algorithm", "rsa"])
    assert invalid.exit_code == 2


def test_store_cli_publishes_create_only_checkpoint(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    checkpoint = SignedLedgerCheckpoint(
        payload=LedgerCheckpointPayload(
            checkpoint_id=uuid4(),
            tenant_id="default",
            ledger_sequence=3,
            ledger_entries=3,
            ledger_head_sha256="a" * 64,
            created_at=now,
            retention_until=now + timedelta(days=30),
        ),
        payload_sha256="b" * 64,
        signing_key_id="release-key",
        signature="signature",
    )

    class Store:
        def __init__(self, _database_url: str) -> None:
            pass

        def create_ledger_checkpoint(self, retention_days: int) -> SignedLedgerCheckpoint:
            assert retention_days == 45
            return checkpoint

    monkeypatch.setattr("aecontrol.cli.ArtifactStore", Store)
    result = CliRunner().invoke(
        app,
        [
            "store",
            "checkpoint",
            "--output",
            str(tmp_path),
            "--retention-days",
            "45",
        ],
    )

    assert result.exit_code == 0
    assert f"checkpoint {checkpoint.payload.checkpoint_id}" in result.output
    exported = list(tmp_path.rglob("*.json"))
    assert len(exported) == 1
    assert exported[0].read_bytes() == checkpoint.canonical_bytes()

    missing_destination = CliRunner().invoke(app, ["store", "checkpoint"])
    assert missing_destination.exit_code == 2
    assert "choose exactly one" in missing_destination.output

    monkeypatch.setattr(
        "aecontrol.cli.checkpoint_sink_from_environment",
        lambda: FileCheckpointSink(tmp_path / "s3"),
    )
    s3_result = CliRunner().invoke(app, ["store", "checkpoint", "--s3", "--retention-days", "45"])
    assert s3_result.exit_code == 0
    assert list((tmp_path / "s3").rglob("*.json"))
