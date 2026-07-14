from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen
from uuid import UUID

from aecontrol.checkpoints import CheckpointPublication, SignedLedgerCheckpoint
from aecontrol.guardrails import (
    ExpectedGuardrailAction,
    GuardrailConfigActivation,
    GuardrailConfigVersion,
    GuardrailEfficacyReport,
    GuardrailsConfig,
    StoredGuardrailEvidence,
    StoredGuardrailEvidenceSummary,
)
from aecontrol.models import (
    Accelerator,
    ArtifactIntegrityReport,
    EvaluationJob,
    EvaluationRun,
    GpuCapacityForecast,
    GpuDemandForecast,
    JobPlacementDiagnostic,
    JobStatus,
    OperationalSnapshot,
    StoredComparison,
    StoredComparisonSummary,
    StoredRunSummary,
)
from aecontrol.tenants import (
    IssuedTenantAPIKey,
    TenantAPIKeyRecord,
    TenantQuotaLimits,
    TenantQuotaRecord,
    TenantQuotaStatus,
    TenantRecord,
    TenantScope,
    TenantStatus,
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

    def gpu_capacity(self) -> GpuCapacityForecast:
        return GpuCapacityForecast.model_validate(
            self.transport.request("GET", "/api/v1/capacity/gpu")
        )

    def gpu_demand(self) -> GpuDemandForecast:
        return GpuDemandForecast.model_validate(
            self.transport.request("GET", "/api/v1/capacity/gpu/demand")
        )

    def verify_artifacts(self) -> ArtifactIntegrityReport:
        return ArtifactIntegrityReport.model_validate(
            self.transport.request("GET", "/api/v1/integrity")
        )

    def ledger_checkpoints(self) -> list[SignedLedgerCheckpoint]:
        payload = self.transport.request("GET", "/api/v1/integrity/checkpoints")
        return [SignedLedgerCheckpoint.model_validate(item) for item in _list(payload)]

    def publish_ledger_checkpoint(self, retention_days: int = 30) -> CheckpointPublication:
        return CheckpointPublication.model_validate(
            self.transport.request(
                "POST",
                "/api/v1/integrity/checkpoints",
                {"retention_days": retention_days},
            )
        )

    def tenants(self) -> list[TenantRecord]:
        payload = self.transport.request("GET", "/api/v1/platform/tenants")
        return [TenantRecord.model_validate(item) for item in _list(payload)]

    def create_tenant(
        self, tenant_id: str, display_name: str, initial_key_id: str = "tenant-admin"
    ) -> IssuedTenantAPIKey:
        return IssuedTenantAPIKey.model_validate(
            self.transport.request(
                "POST",
                "/api/v1/platform/tenants",
                {
                    "tenant_id": tenant_id,
                    "display_name": display_name,
                    "initial_key_id": initial_key_id,
                },
            )
        )

    def set_tenant_status(self, tenant_id: str, status: TenantStatus) -> TenantRecord:
        return TenantRecord.model_validate(
            self.transport.request(
                "PATCH", f"/api/v1/platform/tenants/{tenant_id}", {"status": status}
            )
        )

    def tenant_quota(self, tenant_id: str) -> TenantQuotaRecord:
        return TenantQuotaRecord.model_validate(
            self.transport.request("GET", f"/api/v1/platform/tenants/{tenant_id}/quota")
        )

    def set_tenant_quota(self, tenant_id: str, quota: TenantQuotaLimits) -> TenantQuotaRecord:
        return TenantQuotaRecord.model_validate(
            self.transport.request(
                "PUT",
                f"/api/v1/platform/tenants/{tenant_id}/quota",
                quota.model_dump(mode="json"),
            )
        )

    def current_tenant_quota(self) -> TenantQuotaStatus:
        return TenantQuotaStatus.model_validate(
            self.transport.request("GET", "/api/v1/tenant/quota")
        )

    def tenant(self) -> TenantRecord:
        return TenantRecord.model_validate(self.transport.request("GET", "/api/v1/tenant"))

    def tenant_api_keys(self) -> list[TenantAPIKeyRecord]:
        payload = self.transport.request("GET", "/api/v1/tenant/api-keys")
        return [TenantAPIKeyRecord.model_validate(item) for item in _list(payload)]

    def issue_tenant_api_key(self, key_id: str, scopes: set[TenantScope]) -> IssuedTenantAPIKey:
        return IssuedTenantAPIKey.model_validate(
            self.transport.request(
                "POST",
                "/api/v1/tenant/api-keys",
                {"key_id": key_id, "scopes": sorted(scopes)},
            )
        )

    def revoke_tenant_api_key(self, key_id: str) -> TenantAPIKeyRecord:
        return TenantAPIKeyRecord.model_validate(
            self.transport.request("DELETE", f"/api/v1/tenant/api-keys/{key_id}")
        )

    def guardrail_configs(self) -> list[GuardrailsConfig]:
        payload = self.transport.request("GET", "/api/v1/guardrails/configs")
        return [GuardrailsConfig.model_validate(item) for item in _list(payload)]

    def guardrail_config_versions(self) -> list[GuardrailConfigVersion]:
        payload = self.transport.request("GET", "/api/v1/guardrails/config-versions")
        return [GuardrailConfigVersion.model_validate(item) for item in _list(payload)]

    def register_guardrail_config_version(
        self,
        config_id: str,
        version: str,
        bundle_sha256: str,
        description: str = "",
    ) -> GuardrailConfigVersion:
        return GuardrailConfigVersion.model_validate(
            self.transport.request(
                "POST",
                "/api/v1/guardrails/config-versions",
                {
                    "config_id": config_id,
                    "version": version,
                    "bundle_sha256": bundle_sha256,
                    "description": description,
                },
            )
        )

    def guardrail_config_activations(
        self, config_id: str | None = None
    ) -> list[GuardrailConfigActivation]:
        path = "/api/v1/guardrails/config-activations"
        if config_id is not None:
            path += f"?{urlencode({'config_id': config_id})}"
        payload = self.transport.request("GET", path)
        return [GuardrailConfigActivation.model_validate(item) for item in _list(payload)]

    def activate_guardrail_config(self, config_id: str, version: str) -> GuardrailConfigActivation:
        return GuardrailConfigActivation.model_validate(
            self.transport.request(
                "POST",
                "/api/v1/guardrails/config-activations",
                {"config_id": config_id, "version": version},
            )
        )

    def check_guardrails(
        self,
        model: str,
        config_id: str,
        input_text: str,
        output_text: str | None = None,
        config_version: str | None = None,
        expected_action: ExpectedGuardrailAction | None = None,
    ) -> StoredGuardrailEvidence:
        return StoredGuardrailEvidence.model_validate(
            self.transport.request(
                "POST",
                "/api/v1/guardrails/check",
                {
                    "model": model,
                    "config_id": config_id,
                    "input_text": input_text,
                    "output_text": output_text,
                    "config_version": config_version,
                    "expected_action": expected_action.value
                    if expected_action is not None
                    else None,
                },
            )
        )

    def guardrail_efficacy(
        self,
        *,
        config_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> GuardrailEfficacyReport:
        query = {
            key: value
            for key, value in {
                "config_id": config_id,
                "since": since.isoformat() if since is not None else None,
                "until": until.isoformat() if until is not None else None,
            }.items()
            if value is not None
        }
        path = "/api/v1/guardrails/efficacy"
        if query:
            path += f"?{urlencode(query)}"
        return GuardrailEfficacyReport.model_validate(self.transport.request("GET", path))

    def list_guardrail_evidence(self) -> list[StoredGuardrailEvidenceSummary]:
        payload = self.transport.request("GET", "/api/v1/guardrails/evidence")
        return [StoredGuardrailEvidenceSummary.model_validate(item) for item in _list(payload)]

    def get_guardrail_evidence(self, evidence_id: UUID) -> StoredGuardrailEvidence:
        return StoredGuardrailEvidence.model_validate(
            self.transport.request("GET", f"/api/v1/guardrails/evidence/{evidence_id}")
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
        minimum_gpu_memory_available_mb: int = 0,
        maximum_gpu_utilization_percent: float | None = None,
        required_mig_profile: str | None = None,
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
            "minimum_gpu_memory_available_mb": minimum_gpu_memory_available_mb,
            "maximum_gpu_utilization_percent": maximum_gpu_utilization_percent,
            "required_mig_profile": required_mig_profile,
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

    async def gpu_capacity(self) -> GpuCapacityForecast:
        return await asyncio.to_thread(self._sync.gpu_capacity)

    async def gpu_demand(self) -> GpuDemandForecast:
        return await asyncio.to_thread(self._sync.gpu_demand)

    async def verify_artifacts(self) -> ArtifactIntegrityReport:
        return await asyncio.to_thread(self._sync.verify_artifacts)

    async def ledger_checkpoints(self) -> list[SignedLedgerCheckpoint]:
        return await asyncio.to_thread(self._sync.ledger_checkpoints)

    async def publish_ledger_checkpoint(self, retention_days: int = 30) -> CheckpointPublication:
        return await asyncio.to_thread(self._sync.publish_ledger_checkpoint, retention_days)

    async def tenants(self) -> list[TenantRecord]:
        return await asyncio.to_thread(self._sync.tenants)

    async def create_tenant(
        self, tenant_id: str, display_name: str, initial_key_id: str = "tenant-admin"
    ) -> IssuedTenantAPIKey:
        return await asyncio.to_thread(
            self._sync.create_tenant, tenant_id, display_name, initial_key_id
        )

    async def set_tenant_status(self, tenant_id: str, status: TenantStatus) -> TenantRecord:
        return await asyncio.to_thread(self._sync.set_tenant_status, tenant_id, status)

    async def tenant_quota(self, tenant_id: str) -> TenantQuotaRecord:
        return await asyncio.to_thread(self._sync.tenant_quota, tenant_id)

    async def set_tenant_quota(self, tenant_id: str, quota: TenantQuotaLimits) -> TenantQuotaRecord:
        return await asyncio.to_thread(self._sync.set_tenant_quota, tenant_id, quota)

    async def current_tenant_quota(self) -> TenantQuotaStatus:
        return await asyncio.to_thread(self._sync.current_tenant_quota)

    async def tenant(self) -> TenantRecord:
        return await asyncio.to_thread(self._sync.tenant)

    async def tenant_api_keys(self) -> list[TenantAPIKeyRecord]:
        return await asyncio.to_thread(self._sync.tenant_api_keys)

    async def issue_tenant_api_key(
        self, key_id: str, scopes: set[TenantScope]
    ) -> IssuedTenantAPIKey:
        return await asyncio.to_thread(self._sync.issue_tenant_api_key, key_id, scopes)

    async def revoke_tenant_api_key(self, key_id: str) -> TenantAPIKeyRecord:
        return await asyncio.to_thread(self._sync.revoke_tenant_api_key, key_id)

    async def guardrail_configs(self) -> list[GuardrailsConfig]:
        return await asyncio.to_thread(self._sync.guardrail_configs)

    async def guardrail_config_versions(self) -> list[GuardrailConfigVersion]:
        return await asyncio.to_thread(self._sync.guardrail_config_versions)

    async def register_guardrail_config_version(
        self,
        config_id: str,
        version: str,
        bundle_sha256: str,
        description: str = "",
    ) -> GuardrailConfigVersion:
        return await asyncio.to_thread(
            self._sync.register_guardrail_config_version,
            config_id,
            version,
            bundle_sha256,
            description,
        )

    async def guardrail_config_activations(
        self, config_id: str | None = None
    ) -> list[GuardrailConfigActivation]:
        return await asyncio.to_thread(self._sync.guardrail_config_activations, config_id)

    async def activate_guardrail_config(
        self, config_id: str, version: str
    ) -> GuardrailConfigActivation:
        return await asyncio.to_thread(self._sync.activate_guardrail_config, config_id, version)

    async def check_guardrails(
        self,
        model: str,
        config_id: str,
        input_text: str,
        output_text: str | None = None,
        config_version: str | None = None,
        expected_action: ExpectedGuardrailAction | None = None,
    ) -> StoredGuardrailEvidence:
        return await asyncio.to_thread(
            self._sync.check_guardrails,
            model,
            config_id,
            input_text,
            output_text,
            config_version,
            expected_action,
        )

    async def guardrail_efficacy(
        self,
        *,
        config_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> GuardrailEfficacyReport:
        return await asyncio.to_thread(
            self._sync.guardrail_efficacy,
            config_id=config_id,
            since=since,
            until=until,
        )

    async def list_guardrail_evidence(self) -> list[StoredGuardrailEvidenceSummary]:
        return await asyncio.to_thread(self._sync.list_guardrail_evidence)

    async def get_guardrail_evidence(self, evidence_id: UUID) -> StoredGuardrailEvidence:
        return await asyncio.to_thread(self._sync.get_guardrail_evidence, evidence_id)

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
        minimum_gpu_memory_available_mb: int = 0,
        maximum_gpu_utilization_percent: float | None = None,
        required_mig_profile: str | None = None,
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
            minimum_gpu_memory_available_mb=minimum_gpu_memory_available_mb,
            maximum_gpu_utilization_percent=maximum_gpu_utilization_percent,
            required_mig_profile=required_mig_profile,
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
