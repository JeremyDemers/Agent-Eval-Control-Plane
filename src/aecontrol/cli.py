from __future__ import annotations

import asyncio
import base64
import getpass
import json
import os
import secrets
import shutil
import socket
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID

import typer
import uvicorn
from rich.console import Console

from aecontrol.agents import list_agent_versions
from aecontrol.api import DEFAULT_DATABASE_URL, create_app
from aecontrol.auth import hash_api_key, load_auth_config
from aecontrol.checkpoints import FileCheckpointSink, checkpoint_sink_from_environment
from aecontrol.compare import compare_runs
from aecontrol.database import database_configuration_from_environment
from aecontrol.datasets import validate_jsonl_dataset
from aecontrol.dcgm import dcgm_configuration_from_environment
from aecontrol.engine import EvaluationEngine, load_suite
from aecontrol.federation import oidc_configuration_from_environment
from aecontrol.gate import evaluate_gate, load_policy
from aecontrol.guardrails import GuardrailsClient, GuardrailsError, guardrail_bundle_digest
from aecontrol.hardware import detect_worker_capabilities
from aecontrol.integrity import ED25519, HMAC_SHA256, ArtifactKeyring, generate_ed25519_keypair
from aecontrol.jobs import EvaluationWorker
from aecontrol.models import Accelerator, EvaluationRun, GateOutcome, JobStatus, RunComparison
from aecontrol.nim import NIMClient
from aecontrol.ollama import OllamaClient, OllamaError
from aecontrol.openai_compatible import OpenAICompatibleClient, OpenAICompatibleError
from aecontrol.promotion import PromotionConfiguration, PromotionError, PromotionOrchestrator
from aecontrol.recovery import (
    DEFAULT_MAX_CHECKPOINT_AGE_HOURS,
    DEFAULT_MAX_LEDGER_ENTRIES,
    RecoveryReportPublicationError,
    RecoveryVerificationError,
    RecoveryVerifier,
    S3ObjectLockRecoveryReportSink,
    load_recovery_checkpoint,
    load_recovery_checkpoint_directory,
)
from aecontrol.recovery_drill import (
    InClusterKubernetesClient,
    RecoveryDrillConfiguration,
    RecoveryDrillError,
    RecoveryDrillOrchestrator,
)
from aecontrol.reports import render_html
from aecontrol.sandbox import podman_sandbox_configuration_from_environment
from aecontrol.store import ArtifactStore
from aecontrol.telemetry import (
    configure_telemetry_from_environment,
    shutdown_telemetry,
    telemetry_configuration_from_environment,
)
from aecontrol.tenancy import default_tenant_id
from aecontrol.tenants import TenantQuotaLimits
from aecontrol.vault import vault_configuration_from_environment

app = typer.Typer(help="AgentEval Control Plane CLI")
datasets_app = typer.Typer(help="Dataset commands")
suites_app = typer.Typer(help="Suite commands")
plugins_app = typer.Typer(help="Plugin commands")
agents_app = typer.Typer(help="Agent commands")
store_app = typer.Typer(help="PostgreSQL artifact store commands")
jobs_app = typer.Typer(help="Durable evaluation job commands")
ollama_app = typer.Typer(help="Ollama provider commands")
openai_app = typer.Typer(help="OpenAI-compatible provider commands")
nim_app = typer.Typer(help="NVIDIA NIM provider commands")
guardrails_app = typer.Typer(help="NVIDIA NeMo Guardrails commands")
auth_app = typer.Typer(help="API authentication commands")
tenant_app = typer.Typer(help="Tenant resource-governance commands")
platform_app = typer.Typer(help="Platform operator commands")
app.add_typer(datasets_app, name="datasets")
app.add_typer(suites_app, name="suites")
app.add_typer(plugins_app, name="plugins")
app.add_typer(agents_app, name="agents")
app.add_typer(store_app, name="store")
app.add_typer(jobs_app, name="jobs")
app.add_typer(ollama_app, name="ollama")
app.add_typer(openai_app, name="openai")
app.add_typer(nim_app, name="nim")
app.add_typer(guardrails_app, name="guardrails")
app.add_typer(auth_app, name="auth")
app.add_typer(tenant_app, name="tenant")
app.add_typer(platform_app, name="platform")
console = Console()


@app.command("recovery-drill")
def recovery_drill(json_output: bool = typer.Option(False, "--json")) -> None:
    """Run one in-cluster CloudNativePG restore and verification drill."""
    try:
        configuration = RecoveryDrillConfiguration.from_environment()
        outcome = RecoveryDrillOrchestrator(
            configuration, InClusterKubernetesClient.from_environment()
        ).run()
    except (RecoveryDrillError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    if json_output:
        console.print(outcome.model_dump_json(indent=2))
        return
    console.print(f"recovery drill {outcome.drill_id} passed in {outcome.duration_seconds:.1f}s")
    console.print("report archived: true; restored cluster deleted: true")


@app.command("promote-replica")
def promote_replica(json_output: bool = typer.Option(False, "--json")) -> None:
    """Guard and execute one in-cluster CloudNativePG controlled promotion."""
    try:
        outcome = PromotionOrchestrator(
            PromotionConfiguration.from_environment(),
            InClusterKubernetesClient.from_environment(),
        ).run()
    except (PromotionError, RecoveryDrillError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    if json_output:
        console.print(outcome.model_dump_json(indent=2))
        return
    console.print(f"promoted {outcome.target_cluster} from {outcome.source_cluster}")
    console.print(f"promotion token sha256: {outcome.token_sha256}")


@app.command()
def doctor() -> None:
    console.print("[green]aecontrol doctor ok[/green]")
    console.print(f"python: {sys.version.split()[0]}")
    console.print("runtime: deterministic_coding")
    backend = os.getenv("AECONTROL_SANDBOX_BACKEND", "process")
    console.print(f"sandbox: {backend}")
    if backend == "podman":
        console.print(f"podman: {shutil.which('podman') or 'not found'}")
        sandbox = podman_sandbox_configuration_from_environment()
        pinning = "required" if sandbox.require_digest else "optional"
        console.print(
            f"sandbox image: {'digest-pinned' if sandbox.digest_pinned else 'tagged'} "
            f"(pinning {pinning})"
        )
        console.print(
            "sandbox policies: "
            f"seccomp={'custom' if sandbox.seccomp_profile else 'runtime-default'}, "
            f"apparmor={sandbox.apparmor_profile or 'runtime-default'}"
        )
    database = database_configuration_from_environment()
    if database.pooling_enabled:
        console.print(
            f"database: pooled min={database.pool_min_size} max={database.pool_max_size} "
            f"timeout={database.pool_timeout_seconds:g}s"
        )
    else:
        console.print("database: direct")
    console.print(f"database migration lock: {database.migration_lock_timeout_seconds:g}s")
    console.print(f"tenant: {default_tenant_id()}")
    federation = oidc_configuration_from_environment()
    if federation is None:
        console.print("identity federation: disabled")
    else:
        console.print(
            f"identity federation: enabled issuer={federation.issuer_host} "
            f"algorithms={','.join(federation.algorithms)}"
        )
    keyring = ArtifactKeyring.from_environment()
    vault = vault_configuration_from_environment()
    if vault is not None:
        console.print(
            f"artifact signing: vault-transit host={vault.endpoint_host} "
            f"mount={vault.mount} key_version={vault.key_version}"
        )
    elif keyring is not None and keyring.active_key_id is not None:
        console.print(f"artifact signing: local {keyring.active_algorithm}")
    elif keyring is not None:
        console.print("artifact signing: public-verification-only")
    else:
        console.print("artifact signing: disabled")
    dcgm = dcgm_configuration_from_environment()
    dcgm_detail = (
        f"enabled host={dcgm.endpoint_host} timeout={dcgm.timeout_seconds:g}s pod={dcgm.pod_name}"
        if dcgm.enabled
        else "disabled"
    )
    console.print(f"dcgm exporter: {dcgm_detail}")
    telemetry = telemetry_configuration_from_environment()
    telemetry_detail = (
        f"{telemetry.mode} host={telemetry.endpoint_host}" if telemetry.enabled else telemetry.mode
    )
    console.print(f"telemetry: {telemetry_detail}")


@auth_app.command("hash-key")
def auth_hash_key(secret: str | None = typer.Option(None, "--secret", hidden=True)) -> None:
    """Hash a high-entropy API key for an authentication configuration."""
    resolved = secret if secret is not None else getpass.getpass("API key: ")
    try:
        console.print(hash_api_key(resolved))
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error


@auth_app.command("validate")
def auth_validate(config: Path) -> None:
    """Validate an authentication configuration without exposing key material."""
    auth_config = load_auth_config(config)
    tenants = len({key.tenant_id for key in auth_config.keys})
    console.print(f"[green]valid[/green] {config} keys={len(auth_config.keys)} tenants={tenants}")


@auth_app.command("federation")
def auth_federation() -> None:
    """Validate OIDC environment configuration without contacting the identity provider."""
    try:
        configuration = oidc_configuration_from_environment()
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error
    if configuration is None:
        console.print("identity federation: disabled")
        return
    jwks_host = urlparse(configuration.jwks_url).hostname
    console.print("[green]identity federation: valid[/green]")
    console.print(f"issuer host: {configuration.issuer_host}")
    console.print(f"JWKS host: {jwks_host}")
    console.print(f"audiences: {len(configuration.audiences)}")
    console.print(f"algorithms: {','.join(configuration.algorithms)}")


@tenant_app.command("quota-set")
def tenant_quota_set(
    tenant_id: str = typer.Argument(...),
    max_queued_jobs: int | None = typer.Option(None, min=0),
    max_jobs_per_hour: int | None = typer.Option(None, min=0),
    max_running_jobs: int | None = typer.Option(None, min=0),
    max_running_cuda_jobs: int | None = typer.Option(None, min=0),
    updated_by: str = typer.Option("cli-operator", "--updated-by"),
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Replace a registered tenant's quota policy; omitted limits are unlimited."""
    try:
        quota = TenantQuotaLimits(
            max_queued_jobs=max_queued_jobs,
            max_jobs_per_hour=max_jobs_per_hour,
            max_running_jobs=max_running_jobs,
            max_running_cuda_jobs=max_running_cuda_jobs,
        )
        stored = ArtifactStore(database_url).set_tenant_quota(
            tenant_id, quota, updated_by=updated_by
        )
    except (KeyError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    if json_output:
        console.print(stored.model_dump_json(indent=2))
        return
    console.print(f"tenant quota updated: {stored.tenant_id}")
    console.print(
        f"queued={stored.max_queued_jobs} hourly={stored.max_jobs_per_hour} "
        f"running={stored.max_running_jobs} cuda={stored.max_running_cuda_jobs}"
    )


@tenant_app.command("quota-status")
def tenant_quota_status(
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Show policy and live usage for the tenant selected by AECONTROL_TENANT_ID."""
    try:
        quota_status = ArtifactStore(database_url).tenant_quota_status()
    except KeyError as error:
        raise typer.BadParameter(f"tenant was not found: {error.args[0]}") from error
    if json_output:
        console.print(quota_status.model_dump_json(indent=2))
        return
    quota = quota_status.quota
    usage = quota_status.usage
    console.print(f"tenant quota: {quota.tenant_id}")
    console.print(
        f"queued={usage.queued_jobs}/{quota.max_queued_jobs} "
        f"hourly={usage.jobs_submitted_last_hour}/{quota.max_jobs_per_hour} "
        f"running={usage.active_running_jobs}/{quota.max_running_jobs} "
        f"cuda={usage.active_running_cuda_jobs}/{quota.max_running_cuda_jobs}"
    )


@platform_app.command("fleet")
def platform_fleet(
    active_worker_window_seconds: int = typer.Option(120, min=30, max=3600),
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Show privacy-bounded queue and worker capacity across tenants."""
    report = ArtifactStore(database_url).platform_fleet_report(active_worker_window_seconds)
    if json_output:
        console.print(report.model_dump_json(indent=2))
        return
    totals = report.totals
    console.print(
        f"fleet: tenants={len(report.tenants)} "
        f"queued_cpu={totals.queued_cpu_jobs} queued_cuda={totals.queued_cuda_jobs}"
    )
    console.print(
        f"running_cpu={totals.active_running_cpu_jobs} "
        f"running_cuda={totals.active_running_cuda_jobs} "
        f"active_gpus={totals.active_gpu_devices}"
    )
    for tenant in report.tenants:
        saturated = ",".join(
            name
            for name, value in (
                ("queue", tenant.saturation.queued_jobs),
                ("hourly", tenant.saturation.jobs_per_hour),
                ("running", tenant.saturation.running_jobs),
                ("cuda", tenant.saturation.running_cuda_jobs),
            )
            if value
        )
        console.print(
            f"{tenant.tenant_id} status={tenant.status} "
            f"queue={tenant.queued_cpu_jobs + tenant.queued_cuda_jobs} "
            f"running={tenant.active_running_cpu_jobs + tenant.active_running_cuda_jobs} "
            f"cuda_workers={tenant.active_cuda_workers} gpus={tenant.active_gpu_devices} "
            f"saturated={saturated or 'none'}"
        )


@datasets_app.command("validate")
def datasets_validate(path: Path, json_output: bool = typer.Option(False, "--json")) -> None:
    report = validate_jsonl_dataset(path)
    if json_output:
        console.print(report.model_dump_json(indent=2))
    elif report.valid:
        console.print(f"[green]valid[/green] {path}")
    else:
        for issue in report.issues:
            console.print(f"[red]{issue.location}[/red] {issue.message}")
    if not report.valid:
        raise typer.Exit(2)


@suites_app.command("validate")
def suites_validate(path: Path) -> None:
    suite = load_suite(path)
    report = validate_jsonl_dataset(Path(suite.dataset_path))
    if not report.valid:
        for issue in report.issues:
            console.print(f"[red]{issue.location}[/red] {issue.message}")
        raise typer.Exit(2)
    console.print(f"[green]valid[/green] {suite.name}")


@app.command("run")
def run_suite(
    suite: Path = typer.Option(..., "--suite"),
    agent_version: str = typer.Option(..., "--agent-version"),
    output: Path = typer.Option(..., "--output"),
    database_url: str | None = typer.Option(None, "--database-url", envvar="DATABASE_URL"),
) -> None:
    engine = EvaluationEngine()
    run = asyncio.run(engine.run(load_suite(suite), agent_version))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(run.model_dump_json(indent=2))
    if database_url:
        ArtifactStore(database_url).save_run(run)
    passed = sum(result.hidden_success for result in run.case_results)
    console.print(f"{agent_version}: hidden pass rate {passed}/{len(run.case_results)}")


@app.command()
def compare(
    baseline: Path = typer.Option(..., "--baseline"),
    candidate: Path = typer.Option(..., "--candidate"),
    output: Path = typer.Option(..., "--output"),
) -> None:
    baseline_run = EvaluationRun.model_validate_json(baseline.read_text())
    candidate_run = EvaluationRun.model_validate_json(candidate.read_text())
    comparison = compare_runs(baseline_run, candidate_run)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(comparison.model_dump_json(indent=2))
    console.print(
        f"delta={comparison.aggregate_pass_rate_delta:.2%} regressed={comparison.regressed_cases}"
    )


@app.command()
def gate(
    comparison: Path = typer.Option(..., "--comparison"),
    policy: Path = typer.Option(..., "--policy"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    decision = evaluate_gate(
        RunComparison.model_validate_json(comparison.read_text()), load_policy(policy)
    )
    if json_output:
        console.print(decision.model_dump_json(indent=2))
    else:
        console.print(f"gate: {decision.outcome}")
        for finding in decision.findings:
            console.print(f"- {finding.scope} {finding.metric}: {finding.message}")
    if decision.outcome in {GateOutcome.BLOCK, GateOutcome.INCONCLUSIVE}:
        raise typer.Exit(1)


@app.command()
def report(
    comparison: Path = typer.Option(..., "--comparison"),
    policy: Path = typer.Option(..., "--policy"),
    output: Path = typer.Option(..., "--output"),
    baseline: Path | None = typer.Option(None, "--baseline-run"),
    candidate: Path | None = typer.Option(None, "--candidate-run"),
) -> None:
    comparison_model = RunComparison.model_validate_json(comparison.read_text())
    decision = evaluate_gate(comparison_model, load_policy(policy))
    baseline_run = EvaluationRun.model_validate_json(baseline.read_text()) if baseline else None
    candidate_run = EvaluationRun.model_validate_json(candidate.read_text()) if candidate else None
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_html(comparison_model, decision, baseline_run, candidate_run))
    console.print(f"wrote {output}")


@plugins_app.command("list")
def plugins_list() -> None:
    payload = {
        "runtimes": ["deterministic_coding", "ollama_coding", "openai_compatible_coding"],
        "evaluators": [
            "public_test_success",
            "hidden_test_success",
            "expected_tool_usage",
            "forbidden_tool_usage",
            "expected_file_modification",
            "forbidden_file_modification",
            "patch_scope_score",
            "test_weakening_detection",
            "execution_success",
            "execution_duration",
            "composite_score",
        ],
    }
    console.print(json.dumps(payload, indent=2))


@agents_app.command("versions")
def agent_versions(json_output: bool = typer.Option(False, "--json")) -> None:
    versions = list_agent_versions()
    if json_output:
        console.print(json.dumps([version.model_dump() for version in versions], indent=2))
        return
    for version in versions:
        console.print(f"{version.version}: {version.description}")


@store_app.command("import-run")
def store_import_run(
    run_file: Path = typer.Option(..., "--run"),
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
) -> None:
    run = EvaluationRun.model_validate_json(run_file.read_text())
    ArtifactStore(database_url).save_run(run)
    console.print(f"stored run {run.run_id} ({run.agent_version})")


@store_app.command("list-runs")
def store_list_runs(
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    runs = ArtifactStore(database_url).list_runs()
    if json_output:
        console.print(json.dumps([run.model_dump(mode="json") for run in runs], indent=2))
        return
    for run in runs:
        console.print(
            f"{run.run_id} {run.agent_version} cases={run.case_count} "
            f"hidden_pass={run.hidden_pass_rate:.1%}"
        )


@store_app.command("verify")
def store_verify(
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    report = ArtifactStore(database_url).verify_artifacts()
    if json_output:
        console.print(report.model_dump_json(indent=2))
    else:
        console.print(
            f"artifact verification: {report.valid}/{report.checked} valid "
            f"({report.signed} signed, {report.unsigned} unsigned)"
        )
        if report.signature_algorithms:
            algorithms = ", ".join(
                f"{algorithm}={count}" for algorithm, count in report.signature_algorithms.items()
            )
            console.print(f"signature algorithms: {algorithms}")
        console.print(
            f"artifact ledger: {report.ledger_valid}/{report.ledger_checked} valid "
            f"head={report.ledger_head_sha256}"
        )
        console.print(
            f"ledger checkpoints: {report.checkpoint_valid}/{report.checkpoint_checked} valid"
        )
        for ledger_failure in report.ledger_failures:
            console.print(
                f"- ledger sequence {ledger_failure.sequence}: {ledger_failure.reason} "
                f"({ledger_failure.artifact_type} {ledger_failure.artifact_id})"
            )
        for failure in report.failures:
            console.print(
                f"- {failure.artifact_type} {failure.artifact_id}: {failure.failure_kind} failure"
            )
        for checkpoint_failure in report.checkpoint_failures:
            console.print(
                f"- checkpoint {checkpoint_failure.checkpoint_id}: "
                f"{checkpoint_failure.reason} at sequence {checkpoint_failure.ledger_sequence}"
            )
    if report.failures or report.ledger_failures or report.checkpoint_failures:
        raise typer.Exit(1)


@store_app.command("checkpoint")
def store_checkpoint(
    output: Path | None = typer.Option(None, "--output", help="Create-only checkpoint directory"),
    s3: bool = typer.Option(False, "--s3", help="Publish to configured S3 Object Lock bucket"),
    retention_days: int = typer.Option(30, "--retention-days", min=1, max=3650),
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Sign and publish the current tenant ledger head."""
    if (output is None and not s3) or (output is not None and s3):
        raise typer.BadParameter("choose exactly one of --output or --s3")
    try:
        checkpoint = ArtifactStore(database_url).create_ledger_checkpoint(retention_days)
        if s3:
            sink = checkpoint_sink_from_environment()
            if sink is None:
                raise ValueError("AECONTROL_CHECKPOINT_S3_BUCKET is required with --s3")
            publication = sink.publish(checkpoint)
        else:
            assert output is not None
            publication = FileCheckpointSink(output).publish(checkpoint)
    except (RuntimeError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    if json_output:
        console.print(publication.model_dump_json(indent=2))
        return
    console.print(
        f"checkpoint {checkpoint.payload.checkpoint_id} "
        f"sequence={checkpoint.payload.ledger_sequence} head={checkpoint.payload.ledger_head_sha256}"
    )
    console.print(f"published: {publication.destination}")
    if publication.copies:
        copy_names = ",".join(copy.destination_id for copy in publication.copies)
        console.print(
            f"verified copies: {len(publication.copies)}/{publication.required_copies} "
            f"destinations={copy_names}"
        )
    if publication.failed_destinations:
        console.print(f"failed destinations: {','.join(publication.failed_destinations)}")


@store_app.command("verify-recovery")
def store_verify_recovery(
    checkpoints: list[Path] | None = typer.Option(
        None, "--checkpoint", help="Signed external checkpoint file; repeat for each tenant"
    ),
    checkpoint_directory: Path | None = typer.Option(
        None, "--checkpoint-directory", help="Directory containing signed checkpoint JSON files"
    ),
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    schema: str = typer.Option("public", "--schema"),
    max_checkpoint_age_hours: int = typer.Option(
        DEFAULT_MAX_CHECKPOINT_AGE_HOURS,
        "--max-checkpoint-age-hours",
        min=1,
        max=24 * 30,
    ),
    max_ledger_entries: int = typer.Option(
        DEFAULT_MAX_LEDGER_ENTRIES,
        "--max-ledger-entries",
        min=1,
        max=1_000_000,
    ),
    drill_id: str | None = typer.Option(None, "--drill-id"),
    report_s3: bool = typer.Option(
        False, "--report-s3", help="Archive the canonical report in configured S3 Object Lock"
    ),
    report_retention_days: int = typer.Option(90, "--report-retention-days", min=1, max=3650),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Verify an isolated PostgreSQL recovery without mutating it."""
    try:
        if bool(checkpoints) == (checkpoint_directory is not None):
            raise ValueError("choose exactly one of --checkpoint or --checkpoint-directory")
        if checkpoints:
            envelopes = [load_recovery_checkpoint(path) for path in checkpoints]
        else:
            assert checkpoint_directory is not None
            envelopes = load_recovery_checkpoint_directory(checkpoint_directory)
        verifier = RecoveryVerifier(
            database_url,
            schema=schema,
            keyring=ArtifactKeyring.from_environment(),
            max_checkpoint_age_hours=max_checkpoint_age_hours,
            max_ledger_entries=max_ledger_entries,
        )
        report = verifier.verify(envelopes, drill_id=drill_id)
        publication = None
        if report_s3:
            sink = S3ObjectLockRecoveryReportSink.from_environment()
            if sink is None:
                raise ValueError("AECONTROL_RECOVERY_REPORT_S3_BUCKET is required with --report-s3")
            publication = sink.publish(report, report_retention_days)
    except (
        RecoveryReportPublicationError,
        RecoveryVerificationError,
        RuntimeError,
        ValueError,
    ) as error:
        raise typer.BadParameter(str(error)) from error
    if json_output:
        console.print(report.model_dump_json(indent=2))
    else:
        outcome = "passed" if report.success else "failed"
        console.print(
            f"recovery verification {outcome}: database={report.database} "
            f"schema={report.schema_name} version={report.observed_schema_version}"
        )
        console.print(
            f"read-only={str(report.transaction_read_only).lower()} "
            f"checkpoints={report.checkpoints_valid}/{report.checkpoints_checked} "
            f"ledger_entries={report.entries_checked}"
        )
        for result in report.checkpoint_results:
            console.print(
                f"- tenant={result.tenant_id} checkpoint={result.checkpoint_id} "
                f"sequence={result.ledger_sequence} valid={str(result.valid).lower()}"
            )
        for failure in report.failures:
            location = f" tenant={failure.tenant_id}" if failure.tenant_id else ""
            sequence = (
                f" sequence={failure.ledger_sequence}"
                if failure.ledger_sequence is not None
                else ""
            )
            console.print(f"- failure={failure.code}{location}{sequence}")
        if report.failures_truncated:
            console.print(
                f"- failures truncated: showing {len(report.failures)} of {report.failure_count}"
            )
        if publication is not None:
            console.print(f"archived: {publication.destination}")
    if not report.success:
        raise typer.Exit(1)


@store_app.command("generate-signing-key")
def store_generate_signing_key(
    algorithm: str = typer.Option(HMAC_SHA256, "--algorithm"),
) -> None:
    """Generate HMAC key material or an Ed25519 key pair."""
    if algorithm == HMAC_SHA256:
        console.print(base64.b64encode(secrets.token_bytes(32)).decode("ascii"))
        return
    if algorithm != ED25519:
        raise typer.BadParameter(
            f"must be {HMAC_SHA256!r} or {ED25519!r}", param_hint="--algorithm"
        )
    private_key, public_key = generate_ed25519_keypair()
    console.print_json(
        data={
            "algorithm": ED25519,
            "private_key": base64.b64encode(private_key).decode("ascii"),
            "public_key": base64.b64encode(public_key).decode("ascii"),
        }
    )


@store_app.command("compare")
def store_compare(
    baseline_run_id: UUID = typer.Option(..., "--baseline-run-id"),
    candidate_run_id: UUID = typer.Option(..., "--candidate-run-id"),
    policy: Path = typer.Option(..., "--policy"),
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
) -> None:
    store = ArtifactStore(database_url)
    comparison = compare_runs(store.get_run(baseline_run_id), store.get_run(candidate_run_id))
    artifact = store.save_comparison(comparison, evaluate_gate(comparison, load_policy(policy)))
    console.print(f"stored comparison {artifact.comparison_id}: {artifact.decision.outcome}")


@jobs_app.command("enqueue")
def jobs_enqueue(
    suite: Path = typer.Option(..., "--suite"),
    agent_version: str = typer.Option(..., "--agent-version"),
    priority: int = typer.Option(0, "--priority", min=-100, max=100),
    max_attempts: int = typer.Option(3, "--max-attempts", min=1, max=10),
    accelerator: Accelerator = typer.Option(Accelerator.CPU, "--accelerator"),
    minimum_gpu_memory_mb: int = typer.Option(0, "--minimum-gpu-memory-mb", min=0),
    minimum_cuda_compute_capability: float | None = typer.Option(
        None, "--minimum-cuda-compute-capability", min=1
    ),
    minimum_gpu_memory_available_mb: int = typer.Option(
        0, "--minimum-gpu-memory-available-mb", min=0
    ),
    maximum_gpu_utilization_percent: float | None = typer.Option(
        None, "--maximum-gpu-utilization-percent", min=0, max=100
    ),
    mig_profile: str | None = typer.Option(None, "--mig-profile"),
    label: list[str] | None = typer.Option(None, "--label"),
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
) -> None:
    job = ArtifactStore(database_url).enqueue_job(
        str(suite),
        agent_version,
        priority,
        max_attempts,
        accelerator,
        _parse_labels(label),
        minimum_gpu_memory_mb=minimum_gpu_memory_mb,
        minimum_cuda_compute_capability=minimum_cuda_compute_capability,
        minimum_gpu_memory_available_mb=minimum_gpu_memory_available_mb,
        maximum_gpu_utilization_percent=maximum_gpu_utilization_percent,
        required_mig_profile=mig_profile,
    )
    console.print(f"queued job {job.job_id} ({job.agent_version})")


@jobs_app.command("list")
def jobs_list(
    status: JobStatus | None = typer.Option(None, "--status"),
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    jobs = ArtifactStore(database_url).list_jobs(status=status)
    if json_output:
        console.print(json.dumps([job.model_dump(mode="json") for job in jobs], indent=2))
        return
    for job in jobs:
        requirements: list[str] = []
        if job.minimum_gpu_memory_mb:
            requirements.append(f"gpu_memory>={job.minimum_gpu_memory_mb}MiB")
        if job.minimum_cuda_compute_capability is not None:
            requirements.append(f"compute_capability>={job.minimum_cuda_compute_capability:g}")
        if job.minimum_gpu_memory_available_mb:
            requirements.append(f"gpu_free>={job.minimum_gpu_memory_available_mb}MiB")
        if job.maximum_gpu_utilization_percent is not None:
            requirements.append(f"utilization<={job.maximum_gpu_utilization_percent:g}%")
        if job.required_mig_profile is not None:
            requirements.append(f"mig_profile={job.required_mig_profile}")
        gpu_requirement = f" {' '.join(requirements)}" if requirements else ""
        console.print(
            f"{job.job_id} {job.status} {job.agent_version} "
            f"priority={job.priority} attempts={job.attempts}/{job.max_attempts}{gpu_requirement}"
        )


@jobs_app.command("cancel")
def jobs_cancel(
    job_id: UUID,
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
) -> None:
    job = ArtifactStore(database_url).cancel_job(job_id)
    console.print(f"cancelled job {job.job_id}")


@jobs_app.command("explain")
def jobs_explain(
    job_id: UUID,
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    diagnostic = ArtifactStore(database_url).placement_diagnostic(job_id)
    if json_output:
        console.print(diagnostic.model_dump_json(indent=2))
        return
    state = "schedulable" if diagnostic.schedulable else "blocked"
    console.print(f"job {job_id}: {state}, matching_workers={diagnostic.matching_workers}")
    for blocker in diagnostic.blockers:
        console.print(f"- {blocker}")
    for worker in diagnostic.workers:
        result = "eligible" if worker.eligible else "; ".join(worker.reasons)
        console.print(f"- {worker.worker_id}: {result}")


@jobs_app.command("capacity")
def jobs_capacity(
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    forecast = ArtifactStore(database_url).gpu_capacity_forecast()
    if json_output:
        console.print(forecast.model_dump_json(indent=2))
        return
    console.print(
        f"CUDA queue: {forecast.queued_cuda_jobs} jobs, "
        f"first_wave={forecast.first_wave_jobs}, deferred={forecast.deferred_jobs}, "
        f"blocked={forecast.blocked_jobs}, clearance={forecast.minimum_clearance_waves} waves"
    )
    console.print(
        f"capacity: {forecast.active_cuda_workers} active workers, "
        f"{forecast.active_gpus} GPUs, {forecast.available_gpu_memory_mb} MiB available"
    )
    if forecast.estimated_clearance_seconds is None:
        console.print("historical ETA: unavailable (more matching duration samples required)")
    else:
        console.print(
            f"historical ETA: {forecast.estimated_clearance_seconds:.1f}s "
            f"confidence={forecast.estimate_confidence}"
        )
    for estimate in forecast.duration_estimates:
        profile = estimate.mig_profile or "all-cuda"
        console.print(
            f"- history {profile}: n={estimate.sample_count} "
            f"average={estimate.average_seconds:.1f}s p90={estimate.p90_seconds:.1f}s"
        )
    for job in forecast.jobs:
        worker = f" worker={job.assigned_worker_id}" if job.assigned_worker_id else ""
        console.print(
            f"- {job.job_id} {job.state} priority={job.priority} "
            f"matching_workers={job.matching_workers}{worker}"
        )


@jobs_app.command("demand")
def jobs_demand(
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    forecast = ArtifactStore(database_url).gpu_demand_forecast()
    if json_output:
        console.print(forecast.model_dump_json(indent=2))
        return
    ratio = (
        f"{forecast.projected_capacity_ratio:.1%}"
        if forecast.projected_capacity_ratio is not None
        else "unavailable"
    )
    console.print(
        f"GPU demand ({forecast.horizon_hours}h): arrivals={forecast.predicted_cuda_arrivals:.2f}, "
        f"queued={forecast.current_queued_cuda_jobs}, running={forecast.current_running_cuda_jobs}, "
        f"capacity={ratio}, "
        f"state={forecast.saturation}, confidence={forecast.confidence}"
    )
    busiest = sorted(forecast.hours, key=lambda item: item.predicted_arrivals, reverse=True)[:5]
    for hour in busiest:
        console.print(
            f"- {hour.hour_start.isoformat()}: predicted={hour.predicted_arrivals:.2f} "
            f"history={hour.historical_arrivals}/{hour.historical_occurrences}"
        )


@app.command()
def worker(
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    worker_id: str | None = typer.Option(None, "--worker-id"),
    lease_seconds: int = typer.Option(120, "--lease-seconds", min=3),
    poll_seconds: float = typer.Option(1.0, "--poll-seconds", min=0.05),
    once: bool = typer.Option(False, "--once"),
    label: list[str] | None = typer.Option(None, "--label"),
) -> None:
    """Claim and execute durable evaluation jobs."""
    configure_telemetry_from_environment()
    store: ArtifactStore | None = None
    try:
        resolved_worker_id = worker_id or f"{socket.gethostname()}-{os.getpid()}"
        store = ArtifactStore(
            database_url,
            database_config=database_configuration_from_environment(),
        )
        evaluation_worker = EvaluationWorker(
            store,
            resolved_worker_id,
            lease_seconds,
            capability_provider=lambda: detect_worker_capabilities(_parse_labels(label)),
        )
        if once:
            job = asyncio.run(evaluation_worker.run_once())
            console.print("queue empty" if job is None else f"job {job.job_id}: {job.status}")
            return
        console.print(f"worker {resolved_worker_id} polling for jobs")
        asyncio.run(evaluation_worker.run_forever(poll_seconds))
    finally:
        if store is not None:
            store.close()
        shutdown_telemetry()


@app.command("hardware")
def hardware(json_output: bool = typer.Option(False, "--json")) -> None:
    """Inspect capabilities this worker will advertise."""
    capabilities = detect_worker_capabilities()
    if json_output:
        console.print(capabilities.model_dump_json(indent=2))
        return
    console.print(f"host: {capabilities.hostname} ({capabilities.architecture})")
    console.print("accelerators: " + ", ".join(item.value for item in capabilities.accelerators))
    for gpu in capabilities.gpus:
        telemetry = (
            f", utilization {gpu.utilization_percent:.0f}%, "
            f"memory {gpu.memory_used_mb}/{gpu.memory_total_mb} MiB, "
            f"temperature {gpu.temperature_celsius:.0f} C"
            if gpu.utilization_percent is not None
            and gpu.memory_used_mb is not None
            and gpu.temperature_celsius is not None
            else ""
        )
        console.print(
            f"gpu {gpu.index}: {gpu.name}, compute capability {gpu.compute_capability}{telemetry}, "
            f"telemetry {gpu.telemetry_source}"
        )


def _parse_labels(values: list[str] | None) -> dict[str, str]:
    labels: dict[str, str] = {}
    for value in values or []:
        key, separator, item = value.partition("=")
        if not separator or not key or not item:
            raise typer.BadParameter("labels must use key=value syntax")
        labels[key] = item
    return labels


@ollama_app.command("doctor")
def ollama_doctor() -> None:
    client = OllamaClient()
    try:
        provider_version = asyncio.run(client.version())
        models = asyncio.run(client.models())
    except OllamaError as error:
        console.print(f"[red]unavailable[/red] {error}")
        raise typer.Exit(1) from error
    console.print(f"[green]healthy[/green] Ollama {provider_version}, models={len(models)}")


@ollama_app.command("models")
def ollama_models(json_output: bool = typer.Option(False, "--json")) -> None:
    try:
        models = asyncio.run(OllamaClient().models())
    except OllamaError as error:
        console.print(f"[red]unavailable[/red] {error}")
        raise typer.Exit(1) from error
    if json_output:
        console.print(json.dumps([model.model_dump() for model in models], indent=2))
        return
    for model in models:
        console.print(f"{model.name} {model.size / (1024**3):.1f} GiB {model.digest[:12]}")


@openai_app.command("doctor")
def openai_doctor() -> None:
    try:
        models = asyncio.run(OpenAICompatibleClient().models())
    except OpenAICompatibleError as error:
        console.print(f"[red]unavailable[/red] {error}")
        raise typer.Exit(1) from error
    console.print(f"[green]healthy[/green] OpenAI-compatible endpoint, models={len(models)}")


@openai_app.command("models")
def openai_models(json_output: bool = typer.Option(False, "--json")) -> None:
    try:
        models = asyncio.run(OpenAICompatibleClient().models())
    except OpenAICompatibleError as error:
        console.print(f"[red]unavailable[/red] {error}")
        raise typer.Exit(1) from error
    if json_output:
        console.print(json.dumps([model.model_dump() for model in models], indent=2))
        return
    for model in models:
        console.print(model.id)


@nim_app.command("doctor")
def nim_doctor() -> None:
    """Verify NVIDIA NIM credentials, endpoint reachability, and model discovery."""
    try:
        client = NIMClient()
        models = asyncio.run(client.models())
    except (OpenAICompatibleError, ValueError) as error:
        console.print(f"[red]unavailable[/red] {error}")
        raise typer.Exit(1) from error
    console.print(f"[green]healthy[/green] NVIDIA NIM, models={len(models)}")


@nim_app.command("models")
def nim_models(json_output: bool = typer.Option(False, "--json")) -> None:
    """List models exposed by the configured NVIDIA NIM endpoint."""
    try:
        models = asyncio.run(NIMClient().models())
    except (OpenAICompatibleError, ValueError) as error:
        console.print(f"[red]unavailable[/red] {error}")
        raise typer.Exit(1) from error
    if json_output:
        console.print(json.dumps([model.model_dump() for model in models], indent=2))
        return
    for model in models:
        console.print(model.id)


@nim_app.command("metadata")
def nim_metadata() -> None:
    """Read self-hosted NIM deployment metadata and version information."""
    try:
        client = NIMClient()
        metadata, deployment_version = asyncio.run(client.deployment_info())
    except (OpenAICompatibleError, ValueError) as error:
        console.print(f"[red]unavailable[/red] {error}")
        raise typer.Exit(1) from error
    console.print(json.dumps({"metadata": metadata, "version": deployment_version}, indent=2))


@guardrails_app.command("configs")
def guardrails_configs(json_output: bool = typer.Option(False, "--json")) -> None:
    """List configurations exposed by a NeMo Guardrails server."""
    try:
        configs = asyncio.run(GuardrailsClient().configs())
    except GuardrailsError as error:
        console.print(f"[red]unavailable[/red] {error}")
        raise typer.Exit(1) from error
    if json_output:
        console.print(json.dumps([config.model_dump() for config in configs], indent=2))
        return
    for config in configs:
        console.print(config.id)


@guardrails_app.command("versions")
def guardrails_versions(
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """List immutable locally registered Guardrails configuration versions."""
    versions = ArtifactStore(database_url).list_guardrail_config_versions()
    if json_output:
        console.print(json.dumps([item.model_dump(mode="json") for item in versions], indent=2))
        return
    for item in versions:
        active = " active" if item.active else ""
        console.print(
            f"{item.config_id}@{item.version}{active} sha256={item.bundle_sha256} "
            f"created_by={item.created_by}"
        )


@guardrails_app.command("digest")
def guardrails_digest(config_directory: Path) -> None:
    """Hash a complete NeMo Guardrails configuration directory deterministically."""
    try:
        digest = guardrail_bundle_digest(config_directory)
    except ValueError as error:
        console.print(f"[red]invalid bundle[/red] {error}")
        raise typer.Exit(1) from error
    console.print(digest)


@guardrails_app.command("register")
def guardrails_register(
    config_id: str = typer.Option(..., "--config"),
    version: str = typer.Option(..., "--version"),
    bundle_sha256: str = typer.Option(..., "--bundle-sha256"),
    description: str = typer.Option("", "--description"),
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
) -> None:
    """Register an immutable digest for a deployed configuration bundle."""
    try:
        registered = ArtifactStore(database_url).register_guardrail_config_version(
            config_id,
            version,
            bundle_sha256,
            description=description,
        )
    except ValueError as error:
        console.print(f"[red]registration failed[/red] {error}")
        raise typer.Exit(1) from error
    console.print(f"registered {registered.config_id}@{registered.version}")


@guardrails_app.command("activate")
def guardrails_activate(
    config_id: str = typer.Option(..., "--config"),
    version: str = typer.Option(..., "--version"),
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
) -> None:
    """Verify upstream discovery and append a configuration activation."""
    try:
        configs = asyncio.run(GuardrailsClient().configs())
        if config_id not in {item.id for item in configs}:
            raise GuardrailsError(f"NeMo Guardrails is not serving configuration {config_id!r}")
        activation = ArtifactStore(database_url).activate_guardrail_config(config_id, version)
    except (GuardrailsError, KeyError) as error:
        console.print(f"[red]activation failed[/red] {error}")
        raise typer.Exit(1) from error
    console.print(
        f"activated {activation.config_id}@{activation.version} "
        f"activation={activation.activation_id}"
    )


@guardrails_app.command("activations")
def guardrails_activations(
    config_id: str | None = typer.Option(None, "--config"),
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """List append-only activation and rollback history."""
    activations = ArtifactStore(database_url).list_guardrail_config_activations(config_id)
    if json_output:
        console.print(json.dumps([item.model_dump(mode="json") for item in activations], indent=2))
        return
    for item in activations:
        console.print(
            f"{item.activated_at.isoformat()} {item.config_id}@{item.version} "
            f"by={item.activated_by} activation={item.activation_id}"
        )


@guardrails_app.command("efficacy")
def guardrails_efficacy(
    config_id: str | None = typer.Option(None, "--config"),
    days: int = typer.Option(30, "--days", min=1, max=366),
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Compare labeled Guardrails policy outcomes by configuration version."""
    window_end = datetime.now(UTC)
    report = ArtifactStore(database_url).guardrail_efficacy_report(
        config_id=config_id,
        window_start=window_end - timedelta(days=days),
        window_end=window_end,
    )
    if json_output:
        console.print(report.model_dump_json(indent=2))
        return
    console.print(f"checks={report.total_checks} labeled={report.labeled_checks} window={days}d")
    for item in report.versions:
        version = item.config_version or "unmanaged"
        accuracy = f"{item.accuracy:.1%}" if item.accuracy is not None else "not-measured"
        false_positive_rate = (
            f"{item.false_positive_rate:.1%}"
            if item.false_positive_rate is not None
            else "not-measured"
        )
        console.print(
            f"{item.config_id}@{version} samples={item.sample_count} labeled={item.labeled_count} "
            f"interventions={item.intervention_rate:.1%} accuracy={accuracy} "
            f"false-positive-rate={false_positive_rate}"
        )


@guardrails_app.command("check")
def guardrails_check(
    model: str = typer.Option(..., "--model"),
    config_id: str = typer.Option(..., "--config"),
    input_text: str = typer.Option(..., "--input"),
    output_text: str | None = typer.Option(None, "--output"),
) -> None:
    """Check input or an input/output pair and emit structured rail evidence."""
    try:
        evidence = asyncio.run(GuardrailsClient().check(model, config_id, input_text, output_text))
    except GuardrailsError as error:
        console.print(f"[red]unavailable[/red] {error}")
        raise typer.Exit(1) from error
    console.print(evidence.model_dump_json(indent=2))


@app.command()
def serve(
    database_url: str = typer.Option(DEFAULT_DATABASE_URL, "--database-url", envvar="DATABASE_URL"),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port", min=1, max=65535),
) -> None:
    """Serve the API, OpenAPI contract, and trace explorer."""
    uvicorn.run(create_app(database_url), host=host, port=port)
