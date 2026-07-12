from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import Callable
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen
from uuid import UUID

from aecontrol.models import (
    Accelerator,
    ArtifactIntegrityReport,
    EvaluationJob,
    EvaluationRun,
    JobPlacementDiagnostic,
    JobStatus,
    OperationalSnapshot,
    StoredComparison,
    StoredComparisonSummary,
    StoredRunSummary,
)

JsonObject = dict[str, Any]
TERMINAL_JOB_STATES = {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED}


class AgentEvalAPIError(RuntimeError):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"AgentEval API error {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


class Transport(Protocol):
    def request(self, method: str, path: str, payload: JsonObject | None = None) -> Any: ...


class HttpTransport:
    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 30,
        request_id_factory: Callable[[], str] | None = None,
        api_key: str | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.request_id_factory = request_id_factory
        self.api_key = api_key or os.getenv("AECONTROL_API_KEY")

    def request(self, method: str, path: str, payload: JsonObject | None = None) -> Any:
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self.request_id_factory is not None:
            headers["X-Request-ID"] = self.request_id_factory()
        request = Request(  # noqa: S310
            f"{self.base_url}{path}", data=data, method=method, headers=headers
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:  # noqa: S310
                body = response.read()
        except HTTPError as error:
            detail = _error_detail(error.read())
            raise AgentEvalAPIError(error.code, detail) from error
        except (URLError, TimeoutError) as error:
            raise AgentEvalAPIError(0, str(error)) from error
        if not body:
            return None
        try:
            return json.loads(body)
        except json.JSONDecodeError as error:
            raise AgentEvalAPIError(0, "API returned invalid JSON") from error


class AgentEvalClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        transport: Transport | None = None,
        api_key: str | None = None,
    ) -> None:
        self.transport = transport or HttpTransport(base_url, api_key=api_key)

    def health(self) -> JsonObject:
        return _object(self.transport.request("GET", "/healthz"))

    def operations(self) -> OperationalSnapshot:
        return OperationalSnapshot.model_validate(
            self.transport.request("GET", "/api/v1/operations")
        )

    def verify_artifacts(self) -> ArtifactIntegrityReport:
        return ArtifactIntegrityReport.model_validate(
            self.transport.request("GET", "/api/v1/integrity")
        )

    def enqueue_job(
        self,
        suite_path: str,
        agent_version: str,
        *,
        priority: int = 0,
        max_attempts: int = 3,
        accelerator: Accelerator = Accelerator.CPU,
        labels: dict[str, str] | None = None,
        minimum_gpu_memory_mb: int = 0,
        minimum_cuda_compute_capability: float | None = None,
    ) -> EvaluationJob:
        payload = {
            "suite_path": suite_path,
            "agent_version": agent_version,
            "priority": priority,
            "max_attempts": max_attempts,
            "required_accelerator": accelerator.value,
            "required_labels": labels or {},
            "minimum_gpu_memory_mb": minimum_gpu_memory_mb,
            "minimum_cuda_compute_capability": minimum_cuda_compute_capability,
        }
        return EvaluationJob.model_validate(self.transport.request("POST", "/api/v1/jobs", payload))

    def get_job(self, job_id: UUID) -> EvaluationJob:
        return EvaluationJob.model_validate(self.transport.request("GET", f"/api/v1/jobs/{job_id}"))

    def explain_job(self, job_id: UUID) -> JobPlacementDiagnostic:
        return JobPlacementDiagnostic.model_validate(
            self.transport.request("GET", f"/api/v1/jobs/{job_id}/placement")
        )

    def list_jobs(self, status: JobStatus | None = None) -> list[EvaluationJob]:
        query = f"?{urlencode({'status': status.value})}" if status else ""
        payload = self.transport.request("GET", f"/api/v1/jobs{query}")
        return [EvaluationJob.model_validate(item) for item in _list(payload)]

    def cancel_job(self, job_id: UUID) -> EvaluationJob:
        return EvaluationJob.model_validate(
            self.transport.request("DELETE", f"/api/v1/jobs/{job_id}")
        )

    def wait_for_job(
        self, job_id: UUID, *, timeout_seconds: float = 300, poll_seconds: float = 0.5
    ) -> EvaluationJob:
        if timeout_seconds <= 0 or poll_seconds < 0:
            raise ValueError("timeout must be positive and poll interval non-negative")
        deadline = time.monotonic() + timeout_seconds
        while True:
            job = self.get_job(job_id)
            if job.status in TERMINAL_JOB_STATES:
                return job
            if time.monotonic() >= deadline:
                raise TimeoutError(f"job {job_id} did not finish within {timeout_seconds}s")
            time.sleep(poll_seconds)

    def list_runs(self) -> list[StoredRunSummary]:
        payload = self.transport.request("GET", "/api/v1/runs")
        return [StoredRunSummary.model_validate(item) for item in _list(payload)]

    def run_evaluation(self, suite_path: str, agent_version: str) -> EvaluationRun:
        return EvaluationRun.model_validate(
            self.transport.request(
                "POST",
                "/api/v1/evaluations",
                {"suite_path": suite_path, "agent_version": agent_version},
            )
        )

    def get_run(self, run_id: UUID) -> EvaluationRun:
        return EvaluationRun.model_validate(self.transport.request("GET", f"/api/v1/runs/{run_id}"))

    def list_comparisons(self) -> list[StoredComparisonSummary]:
        payload = self.transport.request("GET", "/api/v1/comparisons")
        return [StoredComparisonSummary.model_validate(item) for item in _list(payload)]

    def get_comparison(self, comparison_id: UUID) -> StoredComparison:
        return StoredComparison.model_validate(
            self.transport.request("GET", f"/api/v1/comparisons/{comparison_id}")
        )

    def create_comparison(
        self, baseline_run_id: UUID, candidate_run_id: UUID, policy_path: str
    ) -> StoredComparison:
        return StoredComparison.model_validate(
            self.transport.request(
                "POST",
                "/api/v1/comparisons",
                {
                    "baseline_run_id": str(baseline_run_id),
                    "candidate_run_id": str(candidate_run_id),
                    "policy_path": policy_path,
                },
            )
        )


class AsyncAgentEvalClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        transport: Transport | None = None,
        api_key: str | None = None,
    ) -> None:
        self._sync = AgentEvalClient(base_url, transport, api_key)

    async def health(self) -> JsonObject:
        return await asyncio.to_thread(self._sync.health)

    async def verify_artifacts(self) -> ArtifactIntegrityReport:
        return await asyncio.to_thread(self._sync.verify_artifacts)

    async def enqueue_job(
        self,
        suite_path: str,
        agent_version: str,
        *,
        priority: int = 0,
        max_attempts: int = 3,
        accelerator: Accelerator = Accelerator.CPU,
        labels: dict[str, str] | None = None,
        minimum_gpu_memory_mb: int = 0,
        minimum_cuda_compute_capability: float | None = None,
    ) -> EvaluationJob:
        return await asyncio.to_thread(
            self._sync.enqueue_job,
            suite_path,
            agent_version,
            priority=priority,
            max_attempts=max_attempts,
            accelerator=accelerator,
            labels=labels,
            minimum_gpu_memory_mb=minimum_gpu_memory_mb,
            minimum_cuda_compute_capability=minimum_cuda_compute_capability,
        )

    async def get_job(self, job_id: UUID) -> EvaluationJob:
        return await asyncio.to_thread(self._sync.get_job, job_id)

    async def explain_job(self, job_id: UUID) -> JobPlacementDiagnostic:
        return await asyncio.to_thread(self._sync.explain_job, job_id)

    async def list_jobs(self, status: JobStatus | None = None) -> list[EvaluationJob]:
        return await asyncio.to_thread(self._sync.list_jobs, status)

    async def cancel_job(self, job_id: UUID) -> EvaluationJob:
        return await asyncio.to_thread(self._sync.cancel_job, job_id)

    async def wait_for_job(
        self, job_id: UUID, *, timeout_seconds: float = 300, poll_seconds: float = 0.5
    ) -> EvaluationJob:
        if timeout_seconds <= 0 or poll_seconds < 0:
            raise ValueError("timeout must be positive and poll interval non-negative")
        deadline = time.monotonic() + timeout_seconds
        while True:
            job = await self.get_job(job_id)
            if job.status in TERMINAL_JOB_STATES:
                return job
            if time.monotonic() >= deadline:
                raise TimeoutError(f"job {job_id} did not finish within {timeout_seconds}s")
            await asyncio.sleep(poll_seconds)

    async def get_run(self, run_id: UUID) -> EvaluationRun:
        return await asyncio.to_thread(self._sync.get_run, run_id)

    async def list_runs(self) -> list[StoredRunSummary]:
        return await asyncio.to_thread(self._sync.list_runs)

    async def run_evaluation(self, suite_path: str, agent_version: str) -> EvaluationRun:
        return await asyncio.to_thread(self._sync.run_evaluation, suite_path, agent_version)

    async def list_comparisons(self) -> list[StoredComparisonSummary]:
        return await asyncio.to_thread(self._sync.list_comparisons)

    async def get_comparison(self, comparison_id: UUID) -> StoredComparison:
        return await asyncio.to_thread(self._sync.get_comparison, comparison_id)

    async def create_comparison(
        self, baseline_run_id: UUID, candidate_run_id: UUID, policy_path: str
    ) -> StoredComparison:
        return await asyncio.to_thread(
            self._sync.create_comparison,
            baseline_run_id,
            candidate_run_id,
            policy_path,
        )

    async def operations(self) -> OperationalSnapshot:
        return await asyncio.to_thread(self._sync.operations)


def _error_detail(body: bytes) -> str:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return body.decode(errors="replace") or "request failed"
    return str(payload.get("detail", payload)) if isinstance(payload, dict) else str(payload)


def _object(value: Any) -> JsonObject:
    if not isinstance(value, dict):
        raise AgentEvalAPIError(0, "API returned a non-object response")
    return value


def _list(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise AgentEvalAPIError(0, "API returned a non-list response")
    return value
