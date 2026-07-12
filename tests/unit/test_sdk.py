from __future__ import annotations

import io
import json
from collections import defaultdict
from typing import Any
from unittest.mock import Mock
from urllib.error import HTTPError, URLError
from uuid import uuid4

import pytest

from aecontrol.models import EvaluationJob, JobStatus
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

    created = client.enqueue_job("suite.yaml", "baseline", priority=7, labels={"pool": "test"})
    completed = client.wait_for_job(created.job_id, poll_seconds=0)

    assert completed.status == JobStatus.COMPLETED
    assert transport.requests[0][2] == {
        "suite_path": "suite.yaml",
        "agent_version": "baseline",
        "priority": 7,
        "max_attempts": 3,
        "required_accelerator": "cpu",
        "required_labels": {"pool": "test"},
        "minimum_gpu_memory_mb": 0,
        "minimum_cuda_compute_capability": None,
    }


def test_client_health_and_job_listing() -> None:
    transport = FakeTransport()
    queued = job_payload(JobStatus.QUEUED)
    transport.add("GET", "/healthz", {"status": "ok"})
    transport.add("GET", "/api/v1/jobs?status=queued", [queued])
    client = AgentEvalClient(transport=transport)

    assert client.health() == {"status": "ok"}
    assert client.list_jobs(JobStatus.QUEUED)[0].status == JobStatus.QUEUED


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
    transport.add(
        "GET",
        "/api/v1/operations",
        {
            "runs_total": 0,
            "comparisons_total": 0,
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
    client = AsyncAgentEvalClient(transport=transport)

    assert await client.health() == {"status": "ok"}
    assert await client.list_runs() == []
    assert await client.list_comparisons() == []


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
