from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from html import escape
from importlib.metadata import version
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from aecontrol.auth import Authenticator, Principal
from aecontrol.compare import compare_runs
from aecontrol.engine import EvaluationEngine, load_suite
from aecontrol.gate import evaluate_gate, load_policy
from aecontrol.guardrails import (
    GuardrailsClient,
    GuardrailsConfig,
    GuardrailsError,
    StoredGuardrailEvidence,
    StoredGuardrailEvidenceSummary,
)
from aecontrol.integrity import ArtifactKeyring, ArtifactVerificationError
from aecontrol.models import (
    Accelerator,
    ArtifactIntegrityReport,
    CaseResult,
    EvaluationJob,
    EvaluationRun,
    GpuCapacityForecast,
    GpuDevice,
    JobPlacementDiagnostic,
    JobStatus,
    OperationalSnapshot,
    StoredComparison,
    StoredComparisonSummary,
    StoredRunSummary,
    WorkerRecord,
)
from aecontrol.observability import render_prometheus
from aecontrol.store import ArtifactStore
from aecontrol.tracing import new_trace, span

DEFAULT_DATABASE_URL = "postgresql://aecontrol@127.0.0.1:55432/aecontrol"
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
request_logger = logging.getLogger("uvicorn.error.aecontrol.requests")


class EvaluationRequest(BaseModel):
    suite_path: str
    agent_version: str


class ComparisonRequest(BaseModel):
    baseline_run_id: UUID
    candidate_run_id: UUID
    policy_path: str


class EvaluationJobRequest(BaseModel):
    suite_path: str
    agent_version: str
    priority: int = Field(default=0, ge=-100, le=100)
    max_attempts: int = Field(default=3, ge=1, le=10)
    required_accelerator: Accelerator = Accelerator.CPU
    required_labels: dict[str, str] = Field(default_factory=dict)
    minimum_gpu_memory_mb: int = Field(default=0, ge=0)
    minimum_cuda_compute_capability: float | None = Field(default=None, ge=1)
    minimum_gpu_memory_available_mb: int = Field(default=0, ge=0)
    maximum_gpu_utilization_percent: float | None = Field(default=None, ge=0, le=100)


class GuardrailCheckRequest(BaseModel):
    model: str = Field(min_length=1, max_length=500)
    config_id: str = Field(min_length=1, max_length=500)
    input_text: str = Field(min_length=1, max_length=1_000_000)
    output_text: str | None = Field(default=None, max_length=1_000_000)


def create_app(
    database_url: str | None = None,
    schema: str = "public",
    auth_config: str | Path | None = None,
    input_root: str | Path | None = None,
    guardrails_client: GuardrailsClient | None = None,
    artifact_keyring: ArtifactKeyring | None = None,
) -> FastAPI:
    resolved_database_url = database_url or os.getenv("DATABASE_URL") or DEFAULT_DATABASE_URL
    resolved_input_root = Path(
        input_root or os.getenv("AECONTROL_INPUT_ROOT") or Path.cwd() / "examples"
    ).resolve()
    if not resolved_input_root.is_dir():
        raise ValueError(f"input root is not a directory: {resolved_input_root}")
    allowed_input_files = _index_input_files(resolved_input_root)
    store = ArtifactStore(resolved_database_url, schema=schema, keyring=artifact_keyring)
    guardrails = guardrails_client or GuardrailsClient()
    authenticator = Authenticator(auth_config)
    require_read = authenticator.require("read")
    require_write = authenticator.require("write")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        store.initialize()
        yield

    application = FastAPI(
        title="AgentEval Control Plane",
        version=version("aecontrol"),
        description=(
            "Durable agent evaluation jobs, normalized trajectories, regression analysis, "
            "and release gates."
        ),
        lifespan=lifespan,
    )
    application.state.store = store
    application.state.authenticator = authenticator
    application.state.guardrails_client = guardrails

    @application.middleware("http")
    async def request_context(request: Request, call_next: RequestResponseEndpoint) -> Response:
        supplied_request_id = request.headers.get("x-request-id", "")
        request_id = (
            supplied_request_id
            if REQUEST_ID_PATTERN.fullmatch(supplied_request_id)
            else str(uuid4())
        )
        trace = new_trace(request.headers.get("traceparent"))
        request.state.request_id = request_id
        request.state.traceparent = trace.traceparent
        started = time.perf_counter()
        response_status = 500
        try:
            with span(
                "http.request",
                trace.traceparent,
                method=request.method,
                path=request.url.path,
            ) as request_span:
                request.state.traceparent = request_span.traceparent
                response = await call_next(request)
            response_status = response.status_code
            response.headers["X-Request-ID"] = request_id
            response.headers["traceparent"] = request.state.traceparent
            duration_ms = (time.perf_counter() - started) * 1000
            response.headers["Server-Timing"] = f"app;dur={duration_ms:.2f}"
            return response
        finally:
            request_logger.info(
                json.dumps(
                    {
                        "event": "http_request",
                        "request_id": request_id,
                        "trace_id": request.state.traceparent.split("-")[1],
                        "method": request.method,
                        "path": request.url.path,
                        "status": response_status,
                        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                        "principal": getattr(
                            getattr(request.state, "principal", None), "key_id", "anonymous"
                        ),
                    },
                    separators=(",", ":"),
                )
            )

    @application.get("/healthz", tags=["operations"])
    def health() -> dict[str, object]:
        return store.health()

    @application.get("/readyz", tags=["operations"])
    def readiness() -> JSONResponse:
        snapshot = store.operational_snapshot()
        queued = snapshot.job_counts.get(JobStatus.QUEUED.value, 0)
        ready = queued == 0 or snapshot.workers_active > 0
        return JSONResponse(
            status_code=200 if ready else 503,
            content={
                "status": "ready" if ready else "degraded",
                "queued_jobs": queued,
                "active_workers": snapshot.workers_active,
                "expired_leases": snapshot.expired_leases,
            },
        )

    @application.get("/metrics", include_in_schema=False)
    def metrics() -> PlainTextResponse:
        workers = store.list_workers()
        return PlainTextResponse(
            render_prometheus(
                store.operational_snapshot(), workers, store.gpu_capacity_forecast(workers)
            ),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @application.get("/api/v1/operations", response_model=OperationalSnapshot, tags=["operations"])
    def operations(_principal: Principal = Depends(require_read)) -> OperationalSnapshot:
        return store.operational_snapshot()

    @application.get(
        "/api/v1/capacity/gpu", response_model=GpuCapacityForecast, tags=["operations"]
    )
    def gpu_capacity(_principal: Principal = Depends(require_read)) -> GpuCapacityForecast:
        return store.gpu_capacity_forecast()

    @application.get(
        "/api/v1/integrity", response_model=ArtifactIntegrityReport, tags=["operations"]
    )
    def integrity(_principal: Principal = Depends(require_read)) -> ArtifactIntegrityReport:
        return store.verify_artifacts()

    @application.get(
        "/api/v1/guardrails/configs",
        response_model=list[GuardrailsConfig],
        tags=["guardrails"],
    )
    async def guardrail_configs(
        _principal: Principal = Depends(require_read),
    ) -> list[GuardrailsConfig]:
        try:
            return await guardrails.configs()
        except GuardrailsError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error

    @application.get(
        "/api/v1/guardrails/evidence",
        response_model=list[StoredGuardrailEvidenceSummary],
        tags=["guardrails"],
    )
    async def list_guardrail_evidence(
        limit: int = 100, _principal: Principal = Depends(require_read)
    ) -> list[StoredGuardrailEvidenceSummary]:
        if not 1 <= limit <= 500:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
        return await asyncio.to_thread(store.list_guardrail_evidence, limit)

    @application.post(
        "/api/v1/guardrails/check",
        response_model=StoredGuardrailEvidence,
        status_code=status.HTTP_201_CREATED,
        tags=["guardrails"],
    )
    async def check_guardrails(
        request: GuardrailCheckRequest,
        _principal: Principal = Depends(require_write),
    ) -> StoredGuardrailEvidence:
        try:
            evidence = await guardrails.check(
                model=request.model,
                config_id=request.config_id,
                input_text=request.input_text,
                output_text=request.output_text,
            )
        except GuardrailsError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error
        return await asyncio.to_thread(store.save_guardrail_evidence, evidence)

    @application.get(
        "/api/v1/guardrails/evidence/{evidence_id}",
        response_model=StoredGuardrailEvidence,
        tags=["guardrails"],
    )
    async def get_guardrail_evidence(
        evidence_id: UUID, _principal: Principal = Depends(require_read)
    ) -> StoredGuardrailEvidence:
        try:
            return await asyncio.to_thread(store.get_guardrail_evidence, evidence_id)
        except KeyError as error:
            raise HTTPException(
                status_code=404, detail="guardrail evidence was not found"
            ) from error
        except ArtifactVerificationError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @application.get("/api/v1/runs", response_model=list[StoredRunSummary], tags=["runs"])
    def list_runs(
        limit: int = 100, _principal: Principal = Depends(require_read)
    ) -> list[StoredRunSummary]:
        if not 1 <= limit <= 500:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
        return store.list_runs(limit)

    @application.get("/api/v1/jobs", response_model=list[EvaluationJob], tags=["jobs"])
    def list_jobs(
        limit: int = 100,
        job_status: JobStatus | None = Query(default=None, alias="status"),
        _principal: Principal = Depends(require_read),
    ) -> list[EvaluationJob]:
        if not 1 <= limit <= 500:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
        return store.list_jobs(limit, job_status)

    @application.post(
        "/api/v1/jobs",
        response_model=EvaluationJob,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["jobs"],
    )
    def enqueue_job(
        request: EvaluationJobRequest,
        http_request: Request,
        _principal: Principal = Depends(require_write),
    ) -> EvaluationJob:
        suite_path = _existing_file(request.suite_path, "suite", allowed_input_files)
        try:
            return store.enqueue_job(
                str(suite_path),
                request.agent_version,
                priority=request.priority,
                max_attempts=request.max_attempts,
                required_accelerator=request.required_accelerator,
                required_labels=request.required_labels,
                minimum_gpu_memory_mb=request.minimum_gpu_memory_mb,
                minimum_cuda_compute_capability=request.minimum_cuda_compute_capability,
                minimum_gpu_memory_available_mb=request.minimum_gpu_memory_available_mb,
                maximum_gpu_utilization_percent=request.maximum_gpu_utilization_percent,
                traceparent=http_request.state.traceparent,
                request_id=http_request.state.request_id,
            )
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @application.get("/api/v1/jobs/{job_id}", response_model=EvaluationJob, tags=["jobs"])
    def get_job(job_id: UUID, _principal: Principal = Depends(require_read)) -> EvaluationJob:
        try:
            return store.get_job(job_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="job was not found") from error

    @application.delete("/api/v1/jobs/{job_id}", response_model=EvaluationJob, tags=["jobs"])
    def cancel_job(job_id: UUID, _principal: Principal = Depends(require_write)) -> EvaluationJob:
        try:
            return store.cancel_job(job_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="job was not found") from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @application.get(
        "/api/v1/jobs/{job_id}/placement",
        response_model=JobPlacementDiagnostic,
        tags=["jobs"],
    )
    def job_placement(
        job_id: UUID, _principal: Principal = Depends(require_read)
    ) -> JobPlacementDiagnostic:
        try:
            return store.placement_diagnostic(job_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="job was not found") from error

    @application.get("/api/v1/workers", response_model=list[WorkerRecord], tags=["workers"])
    def list_workers(_principal: Principal = Depends(require_read)) -> list[WorkerRecord]:
        return store.list_workers()

    @application.post(
        "/api/v1/evaluations",
        response_model=EvaluationRun,
        status_code=status.HTTP_201_CREATED,
        tags=["runs"],
    )
    async def evaluate(
        request: EvaluationRequest, _principal: Principal = Depends(require_write)
    ) -> EvaluationRun:
        suite_path = _existing_file(request.suite_path, "suite", allowed_input_files)
        try:
            run = await EvaluationEngine().run(load_suite(suite_path), request.agent_version)
        except (KeyError, ValueError) as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        store.save_run(run)
        return run

    @application.get("/api/v1/runs/{run_id}", response_model=EvaluationRun, tags=["runs"])
    def get_run(run_id: UUID, _principal: Principal = Depends(require_read)) -> EvaluationRun:
        return _get_run(store, run_id)

    @application.get(
        "/api/v1/runs/{run_id}/cases/{case_id}", response_model=CaseResult, tags=["runs"]
    )
    def get_case(
        run_id: UUID, case_id: str, _principal: Principal = Depends(require_read)
    ) -> CaseResult:
        run = _get_run(store, run_id)
        result = next((item for item in run.case_results if item.case.case_id == case_id), None)
        if result is None:
            raise HTTPException(status_code=404, detail=f"case {case_id} was not found")
        return result

    @application.get(
        "/api/v1/comparisons",
        response_model=list[StoredComparisonSummary],
        tags=["comparisons"],
    )
    def list_comparisons(
        limit: int = 100, _principal: Principal = Depends(require_read)
    ) -> list[StoredComparisonSummary]:
        if not 1 <= limit <= 500:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
        return store.list_comparisons(limit)

    @application.post(
        "/api/v1/comparisons",
        response_model=StoredComparison,
        status_code=status.HTTP_201_CREATED,
        tags=["comparisons"],
    )
    def create_comparison(
        request: ComparisonRequest, _principal: Principal = Depends(require_write)
    ) -> StoredComparison:
        baseline = _get_run(store, request.baseline_run_id)
        candidate = _get_run(store, request.candidate_run_id)
        policy_path = _existing_file(request.policy_path, "policy", allowed_input_files)
        comparison = compare_runs(baseline, candidate)
        decision = evaluate_gate(comparison, load_policy(policy_path))
        return store.save_comparison(comparison, decision)

    @application.get(
        "/api/v1/comparisons/{comparison_id}",
        response_model=StoredComparison,
        tags=["comparisons"],
    )
    def get_comparison(
        comparison_id: UUID, _principal: Principal = Depends(require_read)
    ) -> StoredComparison:
        try:
            return store.get_comparison(comparison_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="comparison was not found") from error
        except ArtifactVerificationError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @application.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard() -> str:
        workers = store.list_workers()
        return _render_dashboard(
            store.list_runs(),
            store.list_comparisons(),
            store.list_jobs(),
            workers,
            store.list_guardrail_evidence(10),
            store.operational_snapshot(),
            store.gpu_capacity_forecast(workers),
        )

    @application.get("/runs/{run_id}", response_class=HTMLResponse, include_in_schema=False)
    def run_detail(run_id: UUID) -> str:
        return _render_run(_get_run(store, run_id))

    @application.get(
        "/comparisons/{comparison_id}", response_class=HTMLResponse, include_in_schema=False
    )
    def comparison_detail(comparison_id: UUID) -> str:
        try:
            artifact = store.get_comparison(comparison_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="comparison was not found") from error
        except ArtifactVerificationError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return _render_comparison(artifact)

    @application.get(
        "/guardrails/evidence/{evidence_id}",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def guardrail_evidence_detail(evidence_id: UUID) -> str:
        try:
            artifact = store.get_guardrail_evidence(evidence_id)
        except KeyError as error:
            raise HTTPException(
                status_code=404, detail="guardrail evidence was not found"
            ) from error
        except ArtifactVerificationError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return _render_guardrail_evidence(artifact)

    return application


def _index_input_files(input_root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    working_directory = Path.cwd().resolve()
    for candidate in input_root.rglob("*"):
        resolved = candidate.resolve()
        if not resolved.is_file() or not resolved.is_relative_to(input_root):
            continue
        files[resolved.relative_to(input_root).as_posix()] = resolved
        if resolved.is_relative_to(working_directory):
            files[resolved.relative_to(working_directory).as_posix()] = resolved
    return files


def _existing_file(value: str, label: str, allowed_files: dict[str, Path]) -> Path:
    path = allowed_files.get(value)
    if path is None:
        raise HTTPException(
            status_code=422,
            detail=f"{label} file is not available under the allowed input root: {value}",
        )
    return path


def _get_run(store: ArtifactStore, run_id: UUID) -> EvaluationRun:
    try:
        return store.get_run(run_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="run was not found") from error
    except ArtifactVerificationError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


def _page(title: str, body: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="data:,">
<title>{escape(title)} | AgentEval</title><style>
:root{{--ink:#171a1f;--muted:#66707b;--line:#d8dde3;--paper:#fff;--wash:#f4f6f8;
--green:#147a4b;--red:#b42318;--amber:#9a6700;--blue:#1769aa}}
*{{box-sizing:border-box}}body{{margin:0;color:var(--ink);background:var(--wash);
font:14px/1.45 system-ui,sans-serif;letter-spacing:0}}header{{background:#111820;color:#fff;
padding:18px 28px;display:flex;align-items:center;justify-content:space-between}}
header a{{color:#fff;text-decoration:none}}header strong{{font-size:20px}}nav{{display:flex;gap:16px}}
main{{max-width:1280px;margin:0 auto;padding:28px}}h1{{font-size:26px;margin:0 0 6px}}
h2{{font-size:17px;margin:26px 0 10px}}p{{margin:5px 0}}.muted{{color:var(--muted)}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin:18px 0}}
.metric{{background:var(--paper);border:1px solid var(--line);border-radius:6px;padding:14px}}
.metric b{{display:block;font-size:22px;margin-top:4px;overflow-wrap:anywhere}}table{{width:100%;border-collapse:collapse;
background:var(--paper);border:1px solid var(--line)}}th,td{{padding:10px 12px;border-bottom:1px solid var(--line);
text-align:left;vertical-align:top}}th{{font-size:12px;text-transform:uppercase;color:var(--muted);background:#f9fafb}}
tr:last-child td{{border-bottom:0}}a{{color:var(--blue)}}.PASS,.passed{{color:var(--green);font-weight:700}}
.BLOCK,.failed,.error,.regressed,.intervened,.blocked{{color:var(--red);font-weight:700}}
.WARN,.queued,.deferred{{color:var(--amber);font-weight:700}}
.completed,.first_wave{{color:var(--green);font-weight:700}}.running{{color:var(--blue);font-weight:700}}
details{{background:#fff;border:1px solid var(--line);border-radius:6px;margin:8px 0;padding:10px 12px}}
summary{{cursor:pointer;font-weight:650}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#111820;color:#e8edf2;
padding:14px;border-radius:5px;font:12px/1.5 ui-monospace,monospace}}.tag{{display:inline-block;border:1px solid var(--line);
border-radius:4px;padding:2px 6px;margin-right:4px;color:var(--muted)}}
@media(max-width:720px){{header{{align-items:flex-start;padding:16px}}main{{padding:18px 12px}}
table{{display:block;overflow-x:auto}}nav{{gap:10px}}}}
</style></head><body><header><a href="/"><strong>AgentEval Control Plane</strong></a>
<nav><a href="/docs">API</a><a href="/redoc">Schema</a><a href="/metrics">Metrics</a></nav></header><main>{body}</main></body></html>"""


def _render_dashboard(
    runs: list[StoredRunSummary],
    comparisons: list[StoredComparisonSummary],
    jobs: list[EvaluationJob],
    workers: list[WorkerRecord],
    guardrail_evidence: list[StoredGuardrailEvidenceSummary],
    snapshot: OperationalSnapshot,
    gpu_capacity: GpuCapacityForecast,
) -> str:
    run_rows = (
        "".join(
            f"<tr><td><a href='/runs/{row.run_id}'>{escape(row.agent_version)}</a></td>"
            f"<td>{escape(row.suite_name)}</td><td>{row.case_count}</td>"
            f"<td>{row.hidden_pass_rate:.1%}</td><td>{_utc_timestamp(row.completed_at)}</td></tr>"
            for row in runs
        )
        or "<tr><td colspan='5'>No persisted runs yet.</td></tr>"
    )
    comparison_rows = (
        "".join(
            f"<tr><td><a href='/comparisons/{row.comparison_id}'>{str(row.comparison_id)[:8]}</a></td>"
            f"<td class='{row.outcome}'>{row.outcome}</td><td>{row.paired_cases}</td>"
            f"<td>{row.aggregate_pass_rate_delta:+.1%}</td><td>{_utc_timestamp(row.created_at)}</td></tr>"
            for row in comparisons
        )
        or "<tr><td colspan='5'>No persisted comparisons yet.</td></tr>"
    )
    job_rows = (
        "".join(
            f"<tr><td><a href='/api/v1/jobs/{row.job_id}/placement'>{str(row.job_id)[:8]}</a></td>"
            f"<td>{escape(row.agent_version)}</td>"
            f"<td class='{row.status}'>{row.status}</td><td>{escape(_job_requirement(row))}</td><td>{row.priority}</td>"
            f"<td>{row.attempts}/{row.max_attempts}</td>"
            f"<td>{escape(row.lease_owner or '-')}</td></tr>"
            for row in jobs
        )
        or "<tr><td colspan='7'>No evaluation jobs yet.</td></tr>"
    )
    worker_rows = (
        "".join(
            f"<tr><td>{escape(row.worker_id)}</td><td>{escape(row.capabilities.hostname)}</td>"
            f"<td>{escape(', '.join(item.value for item in row.capabilities.accelerators))}</td>"
            f"<td>{escape(', '.join(_gpu_summary(gpu) for gpu in row.capabilities.gpus) or '-')}</td>"
            f"<td>{_utc_timestamp(row.last_seen_at)}</td></tr>"
            for row in workers
        )
        or "<tr><td colspan='5'>No workers have registered.</td></tr>"
    )
    guardrail_rows = (
        "".join(
            f"<tr><td><a href='/guardrails/evidence/{row.evidence_id}'>{str(row.evidence_id)[:8]}</a></td>"
            f"<td>{escape(row.config_id)}</td><td>{escape(row.model)}</td>"
            f"<td class='{'passed' if row.passed_through else 'intervened'}'>"
            f"{'Pass-through' if row.passed_through else 'Intervention'}</td>"
            f"<td>{_utc_timestamp(row.created_at)}</td></tr>"
            for row in guardrail_evidence
        )
        or "<tr><td colspan='5'>No Guardrails evidence yet.</td></tr>"
    )
    active_jobs = sum(row.status in {JobStatus.QUEUED, JobStatus.RUNNING} for row in jobs)
    intervention_rate = (
        snapshot.guardrail_interventions_total / snapshot.guardrail_evidence_total
        if snapshot.guardrail_evidence_total
        else 0
    )
    capacity_rows = (
        "".join(
            f"<tr><td>{str(row.job_id)[:8]}</td><td>{escape(row.agent_version)}</td>"
            f"<td>{row.priority}</td><td class='{row.state}'>{escape(row.state.replace('_', ' '))}</td>"
            f"<td>{row.matching_workers}</td><td>{escape(row.assigned_worker_id or '-')}</td></tr>"
            for row in gpu_capacity.jobs
        )
        or "<tr><td colspan='6'>No CUDA jobs are queued.</td></tr>"
    )
    return _page(
        "Runs",
        f"""<h1>Evaluation Runs</h1><p class="muted">Durable agent evidence and release decisions.</p>
<div class="metrics"><div class="metric">Stored runs<b>{len(runs)}</b></div>
<div class="metric">Active jobs<b>{active_jobs}</b></div>
<div class="metric">Comparisons<b>{len(comparisons)}</b></div>
<div class="metric">Safety checks<b>{snapshot.guardrail_evidence_total}</b></div>
<div class="metric">Intervention rate<b>{intervention_rate:.1%}</b></div>
<div class="metric">GPU first wave<b>{gpu_capacity.first_wave_jobs}/{gpu_capacity.queued_cuda_jobs}</b></div>
<div class="metric">GPU clearance<b>{gpu_capacity.minimum_clearance_waves} waves</b></div></div>
<h2>Worker Inventory</h2><table><thead><tr><th>Worker</th><th>Host</th><th>Accelerators</th><th>GPU</th><th>Last Seen</th></tr></thead><tbody>{worker_rows}</tbody></table>
<h2>GPU Capacity Forecast</h2><table><thead><tr><th>Job</th><th>Agent</th><th>Priority</th><th>State</th><th>Matching Workers</th><th>First-Wave Worker</th></tr></thead><tbody>{capacity_rows}</tbody></table>
<h2>Evaluation Queue</h2><table><thead><tr><th>Job</th><th>Agent</th><th>Status</th><th>Requires</th><th>Priority</th><th>Attempts</th><th>Worker</th></tr></thead><tbody>{job_rows}</tbody></table>
<h2>Recent Runs</h2><table><thead><tr><th>Agent</th><th>Suite</th><th>Cases</th><th>Hidden pass</th><th>Completed</th></tr></thead><tbody>{run_rows}</tbody></table>
<h2>Release Decisions</h2><table><thead><tr><th>ID</th><th>Gate</th><th>Pairs</th><th>Delta</th><th>Created</th></tr></thead><tbody>{comparison_rows}</tbody></table>
<h2>Safety Evidence</h2><table><thead><tr><th>ID</th><th>Configuration</th><th>Model</th><th>Result</th><th>Created</th></tr></thead><tbody>{guardrail_rows}</tbody></table>""",
    )


def _gpu_summary(gpu: GpuDevice) -> str:
    telemetry: list[str] = []
    if gpu.utilization_percent is not None:
        telemetry.append(f"{gpu.utilization_percent:.0f}% util")
    if gpu.memory_used_mb is not None:
        telemetry.append(f"{gpu.memory_used_mb}/{gpu.memory_total_mb} MiB")
    if gpu.temperature_celsius is not None:
        telemetry.append(f"{gpu.temperature_celsius:.0f} C")
    suffix = f" ({', '.join(telemetry)})" if telemetry else ""
    return f"GPU {gpu.index}: {gpu.name}{suffix}"


def _utc_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _job_requirement(job: EvaluationJob) -> str:
    requirements = [job.required_accelerator.value]
    if job.minimum_gpu_memory_mb:
        requirements.append(f">={job.minimum_gpu_memory_mb} MiB")
    if job.minimum_cuda_compute_capability is not None:
        requirements.append(f"CC >={job.minimum_cuda_compute_capability:g}")
    if job.minimum_gpu_memory_available_mb:
        requirements.append(f">={job.minimum_gpu_memory_available_mb} MiB free")
    if job.maximum_gpu_utilization_percent is not None:
        requirements.append(f"util <={job.maximum_gpu_utilization_percent:g}%")
    return ", ".join(requirements)


def _render_run(run: EvaluationRun) -> str:
    hidden_passes = sum(result.hidden_success for result in run.case_results)
    ordered_results = sorted(
        run.case_results, key=lambda result: (result.hidden_success, result.case.case_id)
    )
    case_sections = "".join(_render_case(result) for result in ordered_results)
    return _page(
        f"Run {str(run.run_id)[:8]}",
        f"""<h1>{escape(run.agent_version)}</h1><p class="muted">Run {run.run_id}</p>
<div class="metrics"><div class="metric">Cases<b>{len(run.case_results)}</b></div>
<div class="metric">Hidden pass<b>{hidden_passes}/{len(run.case_results)}</b></div>
<div class="metric">Dataset<b>{escape(run.dataset_version)}</b></div></div>
<h2>Case Trajectories</h2>{case_sections}""",
    )


def _render_case(result: CaseResult) -> str:
    tools = [
        escape(str(step.data.get("name", "unknown")))
        for step in result.output.trajectory.steps
        if step.kind == "tool_call"
    ]
    metrics = " ".join(
        f"<span class='tag'>{escape(item.name)} {item.score:.2f}</span>"
        for item in result.evaluator_results
    )
    return f"""<details><summary>{escape(result.case.case_id)} · {escape(result.case.title)}
<span class="{result.status}">{result.status}</span></summary>
<p>{metrics}</p><p><b>Tools:</b> {", ".join(tools)}</p><h3>Patch</h3>
<pre>{escape(result.output.patch)}</pre><h3>Hidden test output</h3>
<pre>{escape(result.output.hidden_test_output)}</pre></details>"""


def _render_comparison(artifact: StoredComparison) -> str:
    comparison = artifact.comparison
    decision = artifact.decision
    findings = (
        "".join(
            f"<tr><td>{escape(item.scope)}</td><td>{escape(item.metric)}</td>"
            f"<td class='{item.outcome}'>{item.outcome}</td><td>{escape(item.message)}</td></tr>"
            for item in decision.findings
        )
        or "<tr><td colspan='4'>No gate findings.</td></tr>"
    )
    cases = "".join(
        f"<tr><td>{escape(item.case_id)}</td><td>{escape(item.slice)}</td>"
        f"<td class='{item.classification}'>{escape(item.classification)}</td>"
        f"<td>{escape(item.explanation)}</td></tr>"
        for item in sorted(
            comparison.case_comparisons,
            key=lambda item: (item.classification != "regressed", item.case_id),
        )
    )
    return _page(
        f"Comparison {str(artifact.comparison_id)[:8]}",
        f"""<h1>Release Decision <span class="{decision.outcome}">{decision.outcome}</span></h1>
<p class="muted">Comparison {artifact.comparison_id}</p><div class="metrics">
<div class="metric">Paired cases<b>{comparison.paired_cases}</b></div>
<div class="metric">Pass-rate delta<b>{comparison.aggregate_pass_rate_delta:+.1%}</b></div>
<div class="metric">Regressions<b>{len(comparison.regressed_cases)}</b></div></div>
<h2>Gate Findings</h2><table><thead><tr><th>Scope</th><th>Metric</th><th>Outcome</th><th>Evidence</th></tr></thead><tbody>{findings}</tbody></table>
<h2>Case Analysis</h2><table><thead><tr><th>Case</th><th>Slice</th><th>Class</th><th>Explanation</th></tr></thead><tbody>{cases}</tbody></table>""",
    )


def _render_guardrail_evidence(artifact: StoredGuardrailEvidence) -> str:
    evidence = artifact.evidence
    status_class = "passed" if evidence.passed_through else "intervened"
    status_label = "Pass-through" if evidence.passed_through else "Intervention"
    activated_rails = json.dumps(
        evidence.activated_rails, indent=2, sort_keys=True, ensure_ascii=True, default=str
    )
    stats = json.dumps(evidence.stats, indent=2, sort_keys=True, ensure_ascii=True, default=str)
    rail_count = (
        len(evidence.activated_rails)
        if isinstance(evidence.activated_rails, (list, dict))
        else int(bool(evidence.activated_rails))
    )
    return _page(
        f"Guardrail evidence {str(artifact.evidence_id)[:8]}",
        f"""<h1>Guardrail Check <span class="{status_class}">{status_label}</span></h1>
<p class="muted">Evidence {artifact.evidence_id} · {_utc_timestamp(artifact.created_at)}</p>
<div class="metrics"><div class="metric">Configuration<b>{escape(evidence.config_id)}</b></div>
<div class="metric">Model<b>{escape(evidence.model)}</b></div>
<div class="metric">Activated rails<b>{rail_count}</b></div></div>
<h2>Submitted Text</h2><pre>{escape(evidence.submitted_text)}</pre>
<h2>Guardrailed Response</h2><pre>{escape(evidence.response_text)}</pre>
<h2>Activated Rails</h2><pre>{escape(activated_rails)}</pre>
<h2>Server Statistics</h2><pre>{escape(stats)}</pre>""",
    )


app = create_app()
