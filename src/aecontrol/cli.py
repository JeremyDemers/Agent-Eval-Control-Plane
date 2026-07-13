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
from pathlib import Path
from uuid import UUID

import typer
import uvicorn
from rich.console import Console

from aecontrol.agents import list_agent_versions
from aecontrol.api import DEFAULT_DATABASE_URL, create_app
from aecontrol.auth import hash_api_key, load_auth_config
from aecontrol.compare import compare_runs
from aecontrol.datasets import validate_jsonl_dataset
from aecontrol.engine import EvaluationEngine, load_suite
from aecontrol.gate import evaluate_gate, load_policy
from aecontrol.guardrails import GuardrailsClient, GuardrailsError
from aecontrol.hardware import detect_worker_capabilities
from aecontrol.jobs import EvaluationWorker
from aecontrol.models import Accelerator, EvaluationRun, GateOutcome, JobStatus, RunComparison
from aecontrol.nim import NIMClient
from aecontrol.ollama import OllamaClient, OllamaError
from aecontrol.openai_compatible import OpenAICompatibleClient, OpenAICompatibleError
from aecontrol.reports import render_html
from aecontrol.store import ArtifactStore

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
console = Console()


@app.command()
def doctor() -> None:
    console.print("[green]aecontrol doctor ok[/green]")
    console.print(f"python: {sys.version.split()[0]}")
    console.print("runtime: deterministic_coding")
    backend = os.getenv("AECONTROL_SANDBOX_BACKEND", "process")
    console.print(f"sandbox: {backend}")
    if backend == "podman":
        console.print(f"podman: {shutil.which('podman') or 'not found'}")


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
    console.print(f"[green]valid[/green] {config} keys={len(auth_config.keys)}")


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
        for failure in report.failures:
            console.print(
                f"- {failure.artifact_type} {failure.artifact_id}: {failure.failure_kind} failure"
            )
    if report.failures:
        raise typer.Exit(1)


@store_app.command("generate-signing-key")
def store_generate_signing_key() -> None:
    """Generate a base64-encoded 256-bit artifact signing key."""
    console.print(base64.b64encode(secrets.token_bytes(32)).decode("ascii"))


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
    resolved_worker_id = worker_id or f"{socket.gethostname()}-{os.getpid()}"
    evaluation_worker = EvaluationWorker(
        ArtifactStore(database_url),
        resolved_worker_id,
        lease_seconds,
        detect_worker_capabilities(_parse_labels(label)),
    )
    if once:
        job = asyncio.run(evaluation_worker.run_once())
        console.print("queue empty" if job is None else f"job {job.job_id}: {job.status}")
        return
    console.print(f"worker {resolved_worker_id} polling for jobs")
    asyncio.run(evaluation_worker.run_forever(poll_seconds))


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
            f"gpu {gpu.index}: {gpu.name}, compute capability {gpu.compute_capability}{telemetry}"
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
