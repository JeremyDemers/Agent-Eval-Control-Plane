from __future__ import annotations

import io
import json
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any
from unittest.mock import Mock
from urllib.error import HTTPError, URLError
from uuid import uuid4

import pytest

from aecontrol.guardrails import (
    ExpectedGuardrailAction,
    GuardrailConfigActivation,
    GuardrailConfigVersion,
    GuardrailEfficacyReport,
    GuardrailEvidence,
    StoredGuardrailEvidence,
)
from aecontrol.models import Accelerator, EvaluationJob, JobStatus
from aecontrol.sdk import (
    AgentEvalAPIError,
    AgentEvalClient,
    AsyncAgentEvalClient,
    HttpTransport,
)


class FakeTransport:
    def __init__(self) -> None:
        self.responses: dict[tuple[str, str], list[Any]] = defaultdict(list)
        self.requests: list[tuple[str, str, dict[str, Any] | None]] = []

    def add(self, method: str, path: str, *responses: Any) -> None:
        self.responses[(method, path)].extend(responses)

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        self.requests.append((method, path, payload))
        return self.responses[(method, path)].pop(0)


def job_payload(status: JobStatus, job_id=None) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    return EvaluationJob(
        job_id=job_id or uuid4(),
        suite_path="suite.yaml",
        agent_version="baseline",
        status=status,
    ).model_dump(mode="json")


def capacity_payload() -> dict[str, Any]:
    return {
        "observed_at": "2026-07-13T18:00:00Z",
        "active_worker_window_seconds": 120,
        "active_cuda_workers": 2,
        "active_gpus": 2,
        "memory_telemetry_gpus": 2,
        "utilization_telemetry_gpus": 2,
        "total_gpu_memory_mb": 106496,
        "available_gpu_memory_mb": 82400,
        "average_gpu_utilization_percent": 20,
        "queued_cuda_jobs": 3,
        "first_wave_jobs": 2,
        "deferred_jobs": 1,
        "blocked_jobs": 0,
        "minimum_clearance_waves": 2,
        "estimated_clearance_seconds": 180,
        "estimate_confidence": "high",
        "duration_estimates": [
            {
                "mig_profile": None,
                "sample_count": 12,
                "average_seconds": 75,
                "p90_seconds": 90,
            }
        ],
        "jobs": [],
    }


def demand_payload() -> dict[str, Any]:
    return {
        "observed_at": "2026-07-13T18:37:00Z",
        "history_start": "2026-05-18T18:37:00Z",
        "lookback_days": 56,
        "horizon_hours": 24,
        "historical_cuda_jobs": 24,
        "observed_history_hours": 1344,
        "current_queued_cuda_jobs": 2,
        "current_running_cuda_jobs": 1,
        "predicted_cuda_arrivals": 3.5,
        "average_cuda_duration_seconds": 600,
        "projected_gpu_seconds": 3900,
        "available_gpu_seconds": 172800,
        "projected_capacity_ratio": 0.022569,
        "active_cuda_workers": 2,
        "confidence": "high",
        "saturation": "within_capacity",
        "hours": [],
    }


def test_sync_client_serializes_and_waits_for_job() -> None:
    transport = FakeTransport()
    queued = job_payload(JobStatus.QUEUED)
    job_id = queued["job_id"]
    transport.add("POST", "/api/v1/jobs", queued)
    transport.add(
        "GET",
        f"/api/v1/jobs/{job_id}",
        queued,
        job_payload(JobStatus.COMPLETED, job_id),
    )
    client = AgentEvalClient(transport=transport)

    created = client.enqueue_job(
        "suite.yaml",
        "baseline",
        priority=7,
        labels={"pool": "test"},
        accelerator=Accelerator.CUDA,
        minimum_gpu_memory_available_mb=4096,
        maximum_gpu_utilization_percent=25,
        required_mig_profile="3g.40gb",
    )
    completed = client.wait_for_job(created.job_id, poll_seconds=0)

    assert completed.status == JobStatus.COMPLETED
    assert transport.requests[0][2] == {
        "suite_path": "suite.yaml",
        "agent_version": "baseline",
        "priority": 7,
        "max_attempts": 3,
        "required_accelerator": "cuda",
        "required_labels": {"pool": "test"},
        "minimum_gpu_memory_mb": 0,
        "minimum_cuda_compute_capability": None,
        "minimum_gpu_memory_available_mb": 4096,
        "maximum_gpu_utilization_percent": 25,
        "required_mig_profile": "3g.40gb",
    }


def test_client_health_and_job_listing() -> None:
    transport = FakeTransport()
    queued = job_payload(JobStatus.QUEUED)
    transport.add("GET", "/healthz", {"status": "ok"})
    transport.add("GET", "/api/v1/jobs?status=queued", [queued])
    client = AgentEvalClient(transport=transport)

    assert client.health() == {"status": "ok"}
    assert client.list_jobs(JobStatus.QUEUED)[0].status == JobStatus.QUEUED


def test_client_reads_gpu_capacity_forecast() -> None:
    transport = FakeTransport()
    transport.add("GET", "/api/v1/capacity/gpu", capacity_payload())

    forecast = AgentEvalClient(transport=transport).gpu_capacity()

    assert forecast.first_wave_jobs == 2
    assert forecast.minimum_clearance_waves == 2


def test_client_reads_gpu_demand_forecast() -> None:
    transport = FakeTransport()
    transport.add("GET", "/api/v1/capacity/gpu/demand", demand_payload())

    forecast = AgentEvalClient(transport=transport).gpu_demand()

    assert forecast.predicted_cuda_arrivals == 3.5
    assert forecast.confidence == "high"


def test_client_explains_job_placement() -> None:
    transport = FakeTransport()
    job_id = uuid4()
    transport.add(
        "GET",
        f"/api/v1/jobs/{job_id}/placement",
        {
            "job_id": str(job_id),
            "job_status": "queued",
            "observed_at": "2026-07-12T20:00:00Z",
            "active_worker_window_seconds": 120,
            "schedulable": False,
            "active_workers": 0,
            "matching_workers": 0,
            "blockers": ["no workers are registered"],
            "workers": [],
        },
    )
    diagnostic = AgentEvalClient(transport=transport).explain_job(job_id)
    assert diagnostic.schedulable is False
    assert diagnostic.blockers == ["no workers are registered"]


def test_client_collections_operations_and_cancellation() -> None:
    transport = FakeTransport()
    cancelled = job_payload(JobStatus.CANCELLED)
    job_id = cancelled["job_id"]
    transport.add("DELETE", f"/api/v1/jobs/{job_id}", cancelled)
    transport.add("GET", "/api/v1/runs", [])
    transport.add("GET", "/api/v1/comparisons", [])
    transport.add("GET", "/api/v1/integrity", {"checked": 2, "valid": 2, "failures": []})
    transport.add(
        "GET",
        "/api/v1/operations",
        {
            "runs_total": 0,
            "comparisons_total": 0,
            "guardrail_evidence_total": 0,
            "guardrail_interventions_total": 0,
            "job_counts": {"cancelled": 1},
            "gate_counts": {},
            "workers_registered": 0,
            "workers_active": 0,
            "expired_leases": 0,
            "oldest_queued_seconds": 0,
            "average_completed_job_seconds": 0,
        },
    )
    client = AgentEvalClient(transport=transport)

    assert client.cancel_job(job_id).status == JobStatus.CANCELLED
    assert client.list_runs() == []
    assert client.list_comparisons() == []
    assert client.operations().job_counts == {"cancelled": 1}
    assert client.verify_artifacts().valid == 2


def test_client_guardrail_evidence_workflow() -> None:
    transport = FakeTransport()
    artifact = StoredGuardrailEvidence(
        evidence=GuardrailEvidence(
            config_id="safety",
            model="nim/model",
            submitted_text="candidate",
            response_text="blocked",
            passed_through=False,
        )
    )
    payload = artifact.model_dump(mode="json")
    summary = {
        "evidence_id": payload["evidence_id"],
        "created_at": payload["created_at"],
        "config_id": "safety",
        "model": "nim/model",
        "passed_through": False,
    }
    transport.add("GET", "/api/v1/guardrails/configs", [{"id": "safety"}])
    transport.add("POST", "/api/v1/guardrails/check", payload)
    transport.add("GET", "/api/v1/guardrails/evidence", [summary])
    transport.add("GET", f"/api/v1/guardrails/evidence/{artifact.evidence_id}", payload)
    client = AgentEvalClient(transport=transport)

    assert client.guardrail_configs()[0].id == "safety"
    created = client.check_guardrails("nim/model", "safety", "request", "candidate")
    assert created.evidence.passed_through is False
    assert client.list_guardrail_evidence()[0].config_id == "safety"
    assert client.get_guardrail_evidence(artifact.evidence_id) == artifact
    assert transport.requests[1][2] == {
        "model": "nim/model",
        "config_id": "safety",
        "input_text": "request",
        "output_text": "candidate",
        "config_version": None,
        "expected_action": None,
    }


def test_client_reads_filtered_guardrail_efficacy() -> None:
    transport = FakeTransport()
    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = datetime(2026, 7, 31, tzinfo=UTC)
    report = GuardrailEfficacyReport(
        window_start=start,
        window_end=end,
        config_id="content_safety",
        total_checks=0,
        labeled_checks=0,
        versions=[],
    )
    path = (
        "/api/v1/guardrails/efficacy?config_id=content_safety&"
        "since=2026-07-01T00%3A00%3A00%2B00%3A00&until=2026-07-31T00%3A00%3A00%2B00%3A00"
    )
    transport.add("GET", path, report.model_dump(mode="json"))

    loaded = AgentEvalClient(transport=transport).guardrail_efficacy(
        config_id="content_safety", since=start, until=end
    )

    assert loaded == report
    assert transport.requests[0][1] == path


def test_client_manages_guardrail_configuration_lifecycle() -> None:
    transport = FakeTransport()
    version = GuardrailConfigVersion(
        config_id="content_safety",
        version="2026.07.1",
        bundle_sha256="a" * 64,
        description="release policy",
        created_by="administrator",
    )
    activation = GuardrailConfigActivation(
        config_id=version.config_id,
        version=version.version,
        bundle_sha256=version.bundle_sha256,
        activated_by="administrator",
    )
    version_payload = version.model_dump(mode="json")
    activation_payload = activation.model_dump(mode="json")
    transport.add("GET", "/api/v1/guardrails/config-versions", [version_payload])
    transport.add("POST", "/api/v1/guardrails/config-versions", version_payload)
    transport.add(
        "GET",
        "/api/v1/guardrails/config-activations?config_id=content_safety",
        [activation_payload],
    )
    transport.add("POST", "/api/v1/guardrails/config-activations", activation_payload)
    client = AgentEvalClient(transport=transport)

    assert client.guardrail_config_versions() == [version]
    assert (
        client.register_guardrail_config_version(
            "content_safety", "2026.07.1", "a" * 64, "release policy"
        )
        == version
    )
    assert client.guardrail_config_activations("content_safety") == [activation]
    assert client.activate_guardrail_config("content_safety", "2026.07.1") == activation
    assert transport.requests[1][2] == {
        "config_id": "content_safety",
        "version": "2026.07.1",
        "bundle_sha256": "a" * 64,
        "description": "release policy",
    }
    assert transport.requests[3][2] == {
        "config_id": "content_safety",
        "version": "2026.07.1",
    }


def test_wait_validation_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = FakeTransport()
    queued = job_payload(JobStatus.QUEUED)
    job_id = queued["job_id"]
    transport.add("GET", f"/api/v1/jobs/{job_id}", queued)
    client = AgentEvalClient(transport=transport)

    with pytest.raises(ValueError, match="timeout must be positive"):
        client.wait_for_job(job_id, timeout_seconds=0)

    ticks = iter([0.0, 1.0])
    monkeypatch.setattr("aecontrol.sdk.time.monotonic", lambda: next(ticks))
    with pytest.raises(TimeoutError, match="did not finish"):
        client.wait_for_job(job_id, timeout_seconds=0.5, poll_seconds=0)


@pytest.mark.asyncio
async def test_async_client_wraps_transport_and_terminal_wait() -> None:
    transport = FakeTransport()
    completed = job_payload(JobStatus.COMPLETED)
    job_id = completed["job_id"]
    transport.add("GET", f"/api/v1/jobs/{job_id}", completed)

    result = await AsyncAgentEvalClient(transport=transport).wait_for_job(job_id, poll_seconds=0)

    assert result.status == JobStatus.COMPLETED


@pytest.mark.asyncio
async def test_async_client_health_and_collections() -> None:
    transport = FakeTransport()
    transport.add("GET", "/healthz", {"status": "ok"})
    transport.add("GET", "/api/v1/runs", [])
    transport.add("GET", "/api/v1/comparisons", [])
    transport.add("GET", "/api/v1/capacity/gpu", capacity_payload())
    transport.add("GET", "/api/v1/capacity/gpu/demand", demand_payload())
    client = AsyncAgentEvalClient(transport=transport)

    assert await client.health() == {"status": "ok"}
    assert await client.list_runs() == []
    assert await client.list_comparisons() == []
    assert (await client.gpu_capacity()).active_cuda_workers == 2
    assert (await client.gpu_demand()).saturation == "within_capacity"


@pytest.mark.asyncio
async def test_async_client_guardrail_evidence_workflow() -> None:
    transport = FakeTransport()
    artifact = StoredGuardrailEvidence(
        evidence=GuardrailEvidence(
            config_id="safety",
            model="nim/model",
            submitted_text="candidate",
            response_text="candidate",
            passed_through=True,
        )
    )
    payload = artifact.model_dump(mode="json")
    transport.add("POST", "/api/v1/guardrails/check", payload)
    transport.add("GET", f"/api/v1/guardrails/evidence/{artifact.evidence_id}", payload)
    client = AsyncAgentEvalClient(transport=transport)

    created = await client.check_guardrails(
        "nim/model",
        "safety",
        "request",
        "candidate",
        expected_action=ExpectedGuardrailAction.PASS_THROUGH,
    )
    assert created.evidence.passed_through is True
    assert await client.get_guardrail_evidence(artifact.evidence_id) == artifact
    assert transport.requests[0][2]["expected_action"] == "pass_through"


def test_http_transport_validates_url_and_decodes_response(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="absolute HTTP"):
        HttpTransport("file:///tmp/socket")

    response = Mock()
    response.read.return_value = b'{"status":"ok"}'
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=None)
    opened = Mock(return_value=response)
    monkeypatch.setattr("aecontrol.sdk.urlopen", opened)
    transport = HttpTransport(
        "http://localhost:8000/", request_id_factory=lambda: "sdk-1", api_key="secret"
    )

    assert transport.request("GET", "/healthz") == {"status": "ok"}
    request = opened.call_args.args[0]
    assert request.headers["X-request-id"] == "sdk-1"
    assert request.headers["Authorization"] == "Bearer secret"


def test_http_transport_reads_api_key_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AECONTROL_API_KEY", "environment-secret")
    transport = HttpTransport("http://localhost")
    assert transport.api_key == "environment-secret"


def test_http_transport_normalizes_server_and_connection_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = HTTPError(
        "http://localhost/jobs",
        422,
        "invalid",
        {},
        io.BytesIO(json.dumps({"detail": "bad suite"}).encode()),
    )
    monkeypatch.setattr("aecontrol.sdk.urlopen", Mock(side_effect=error))
    with pytest.raises(AgentEvalAPIError, match="bad suite") as raised:
        HttpTransport("http://localhost").request("GET", "/jobs")
    assert raised.value.status_code == 422

    monkeypatch.setattr("aecontrol.sdk.urlopen", Mock(side_effect=URLError("offline")))
    with pytest.raises(AgentEvalAPIError) as offline:
        HttpTransport("http://localhost").request("GET", "/healthz")
    assert offline.value.status_code == 0


def test_http_transport_handles_empty_and_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    response = Mock()
    response.read.side_effect = [b"", b"not-json"]
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=None)
    monkeypatch.setattr("aecontrol.sdk.urlopen", Mock(return_value=response))
    transport = HttpTransport("http://localhost")

    assert transport.request("DELETE", "/resource") is None
    with pytest.raises(AgentEvalAPIError, match="invalid JSON"):
        transport.request("GET", "/resource")
