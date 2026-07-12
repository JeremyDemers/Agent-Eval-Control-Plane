from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql

from aecontrol.api import DEFAULT_DATABASE_URL, create_app
from aecontrol.jobs import EvaluationWorker
from aecontrol.models import Accelerator, JobStatus, WorkerCapabilities
from aecontrol.store import ArtifactStore


@pytest.fixture
def database_url() -> str:
    return os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)


@pytest.fixture
def api_client(database_url: str) -> TestClient:
    schema = f"test_{uuid4().hex}"
    with TestClient(create_app(database_url, schema=schema)) as client:
        yield client
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def test_persisted_evaluation_comparison_and_trace_flow(api_client: TestClient) -> None:
    health = api_client.get("/healthz", headers={"X-Request-ID": "integration-request"})
    assert health.status_code == 200
    assert health.json()["schema_version"] == 1
    assert health.headers["x-request-id"] == "integration-request"
    assert health.headers["server-timing"].startswith("app;dur=")

    readiness = api_client.get("/readyz")
    assert readiness.status_code == 200
    assert readiness.json()["status"] == "ready"

    baseline = api_client.post(
        "/api/v1/evaluations",
        json={
            "suite_path": "examples/suites/coding_repair.yaml",
            "agent_version": "baseline",
        },
    )
    regressed = api_client.post(
        "/api/v1/evaluations",
        json={
            "suite_path": "examples/suites/coding_repair.yaml",
            "agent_version": "candidate_regressed",
        },
    )
    assert baseline.status_code == 201
    assert regressed.status_code == 201

    baseline_id = baseline.json()["run_id"]
    regressed_id = regressed.json()["run_id"]
    runs = api_client.get("/api/v1/runs")
    assert runs.status_code == 200
    assert {item["run_id"] for item in runs.json()} == {baseline_id, regressed_id}

    case = api_client.get(f"/api/v1/runs/{regressed_id}/cases/SEC-01")
    assert case.status_code == 200
    assert case.json()["case"]["slice"] == "security_sensitive"
    assert case.json()["output"]["trajectory"]["steps"]

    comparison = api_client.post(
        "/api/v1/comparisons",
        json={
            "baseline_run_id": baseline_id,
            "candidate_run_id": regressed_id,
            "policy_path": "examples/policies/coding_repair_gate.yaml",
        },
    )
    assert comparison.status_code == 201
    payload = comparison.json()
    assert payload["decision"]["outcome"] == "BLOCK"
    assert payload["comparison"]["regressed_cases"] == ["SEC-01", "SEC-04"]

    dashboard = api_client.get("/")
    assert dashboard.status_code == 200
    assert "candidate_regressed" in dashboard.text
    assert "Release Decisions" in dashboard.text

    detail = api_client.get(f"/comparisons/{payload['comparison_id']}")
    assert detail.status_code == 200
    assert "security_sensitive" in detail.text

    metrics = api_client.get("/metrics")
    assert metrics.status_code == 200
    assert "aecontrol_runs_total 2" in metrics.text
    assert 'aecontrol_gate_decisions{outcome="BLOCK"} 1' in metrics.text


def test_api_returns_actionable_not_found_responses(api_client: TestClient) -> None:
    missing = api_client.get(f"/api/v1/runs/{uuid4()}")
    assert missing.status_code == 404
    assert missing.json() == {"detail": "run was not found"}

    bad_suite = api_client.post(
        "/api/v1/evaluations",
        json={"suite_path": "missing.yaml", "agent_version": "baseline"},
    )
    assert bad_suite.status_code == 422
    assert "suite file was not found" in bad_suite.json()["detail"]

    generated_id = api_client.get("/healthz", headers={"X-Request-ID": "invalid id!"})
    assert generated_id.headers["x-request-id"] != "invalid id!"


def test_durable_job_runs_to_completion(api_client: TestClient) -> None:
    queued = api_client.post(
        "/api/v1/jobs",
        json={
            "suite_path": "examples/suites/coding_repair.yaml",
            "agent_version": "candidate_fixed",
            "priority": 10,
            "max_attempts": 2,
        },
    )
    assert queued.status_code == 202
    assert queued.json()["status"] == "queued"

    store: ArtifactStore = api_client.app.state.store
    completed = asyncio.run(EvaluationWorker(store, "test-worker").run_once())
    assert completed is not None
    assert completed.status == JobStatus.COMPLETED
    assert completed.attempts == 1
    assert completed.run_id is not None

    persisted = api_client.get(f"/api/v1/jobs/{completed.job_id}")
    assert persisted.status_code == 200
    assert persisted.json()["run_id"] == str(completed.run_id)
    assert api_client.get(f"/api/v1/runs/{completed.run_id}").status_code == 200
    workers = api_client.get("/api/v1/workers")
    assert workers.status_code == 200
    assert workers.json()[0]["worker_id"] == "test-worker"
    assert "Evaluation Queue" in api_client.get("/").text
    operations = api_client.get("/api/v1/operations")
    assert operations.status_code == 200
    assert operations.json()["job_counts"] == {"completed": 1}
    assert operations.json()["workers_active"] == 1


def test_concurrent_workers_claim_job_once_and_failures_retry(api_client: TestClient) -> None:
    store: ArtifactStore = api_client.app.state.store
    single_job = store.enqueue_job("examples/suites/coding_repair.yaml", "baseline", max_attempts=2)

    with ThreadPoolExecutor(max_workers=8) as executor:
        claims = list(
            executor.map(
                lambda worker_id: store.lease_job(worker_id, 120),
                [f"worker-{index}" for index in range(8)],
            )
        )
    claimed = [job for job in claims if job is not None]
    assert len(claimed) == 1
    assert claimed[0].job_id == single_job.job_id
    renewed = store.renew_job_lease(single_job.job_id, claimed[0].lease_owner or "", 180)
    assert renewed.lease_expires_at is not None
    cancelled = store.cancel_job(single_job.job_id)
    assert cancelled.status == JobStatus.CANCELLED
    with pytest.raises(ValueError, match="cannot be cancelled"):
        store.cancel_job(single_job.job_id)

    retrying = store.enqueue_job("missing-suite.yaml", "baseline", max_attempts=2)
    first_attempt = asyncio.run(EvaluationWorker(store, "retry-worker").run_once())
    assert first_attempt is not None
    assert first_attempt.job_id == retrying.job_id
    assert first_attempt.status == JobStatus.QUEUED
    assert first_attempt.error is not None

    second_attempt = asyncio.run(EvaluationWorker(store, "retry-worker").run_once())
    assert second_attempt is not None
    assert second_attempt.status == JobStatus.FAILED
    assert second_attempt.attempts == 2


def test_capability_aware_job_placement(api_client: TestClient) -> None:
    store: ArtifactStore = api_client.app.state.store
    cuda_job = store.enqueue_job(
        "examples/suites/coding_repair.yaml",
        "baseline",
        required_accelerator=Accelerator.CUDA,
        required_labels={"pool": "accelerated"},
    )
    cpu_worker = WorkerCapabilities(
        hostname="cpu-host",
        operating_system="linux",
        architecture="x86_64",
        cpu_count=8,
        accelerators=[Accelerator.CPU],
        labels={"pool": "accelerated"},
    )
    assert store.lease_job("cpu-worker", capabilities=cpu_worker) is None

    cuda_worker = cpu_worker.model_copy(
        update={"accelerators": [Accelerator.CPU, Accelerator.CUDA]}
    )
    claimed = store.lease_job("cuda-worker", capabilities=cuda_worker)
    assert claimed is not None
    assert claimed.job_id == cuda_job.job_id
    store.cancel_job(cuda_job.job_id)


def test_readiness_detects_queued_work_without_workers(api_client: TestClient) -> None:
    queued = api_client.post(
        "/api/v1/jobs",
        json={
            "suite_path": "examples/suites/coding_repair.yaml",
            "agent_version": "baseline",
        },
    )
    assert queued.status_code == 202

    readiness = api_client.get("/readyz")
    assert readiness.status_code == 503
    assert readiness.json() == {
        "status": "degraded",
        "queued_jobs": 1,
        "active_workers": 0,
        "expired_leases": 0,
    }
