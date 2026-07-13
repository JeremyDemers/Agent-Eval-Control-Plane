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
from aecontrol.auth import hash_api_key
from aecontrol.guardrails import GuardrailEvidence, GuardrailsConfig, GuardrailsError
from aecontrol.jobs import EvaluationWorker
from aecontrol.models import Accelerator, GpuDevice, JobStatus, WorkerCapabilities
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


def test_schema_v1_is_migrated_in_place(database_url: str) -> None:
    schema = f"test_{uuid4().hex}"
    try:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
            connection.execute(
                sql.SQL("CREATE TABLE {}.schema_metadata (version INTEGER NOT NULL)").format(
                    sql.Identifier(schema)
                )
            )
            connection.execute(
                sql.SQL("INSERT INTO {}.schema_metadata(version) VALUES (1)").format(
                    sql.Identifier(schema)
                )
            )

        store = ArtifactStore(database_url, schema=schema)
        assert store.health()["schema_version"] == 6
    finally:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_scoped_api_key_authentication(database_url: str, tmp_path) -> None:  # type: ignore[no-untyped-def]
    schema = f"test_{uuid4().hex}"
    auth_config = tmp_path / "auth.yaml"
    auth_config.write_text(
        "keys:\n"
        f"  - key_id: observer\n    secret_sha256: {hash_api_key('read-secret')}\n"
        "    scopes: [read]\n"
        f"  - key_id: operator\n    secret_sha256: {hash_api_key('write-secret')}\n"
        "    scopes: [read, write]\n"
    )
    try:
        with TestClient(create_app(database_url, schema=schema, auth_config=auth_config)) as client:
            assert client.get("/healthz").status_code == 200
            assert client.get("/").status_code == 200

            missing = client.get("/api/v1/runs")
            assert missing.status_code == 401
            assert missing.headers["www-authenticate"] == "Bearer"
            assert missing.json() == {"detail": "API key is required"}

            invalid = client.get("/api/v1/runs", headers={"Authorization": "Bearer wrong-secret"})
            assert invalid.status_code == 401
            assert invalid.json() == {"detail": "API key is invalid"}

            observer_headers = {"Authorization": "Bearer read-secret"}
            assert client.get("/api/v1/runs", headers=observer_headers).status_code == 200
            forbidden = client.post(
                "/api/v1/jobs",
                headers=observer_headers,
                json={
                    "suite_path": "examples/suites/coding_repair.yaml",
                    "agent_version": "baseline",
                },
            )
            assert forbidden.status_code == 403
            assert forbidden.json() == {"detail": "API key requires the write scope"}

            operator_headers = {"Authorization": "Bearer write-secret"}
            queued = client.post(
                "/api/v1/jobs",
                headers=operator_headers,
                json={
                    "suite_path": "examples/suites/coding_repair.yaml",
                    "agent_version": "baseline",
                },
            )
            assert queued.status_code == 202

            security = client.get("/openapi.json").json()["components"]["securitySchemes"]
            assert security["ControlPlaneAPIKey"]["scheme"] == "bearer"
    finally:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_persisted_evaluation_comparison_and_trace_flow(api_client: TestClient) -> None:
    health = api_client.get("/healthz", headers={"X-Request-ID": "integration-request"})
    assert health.status_code == 200
    assert health.json()["schema_version"] == 6
    assert health.headers["x-request-id"] == "integration-request"
    assert health.headers["traceparent"].startswith("00-")
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

    integrity = api_client.get("/api/v1/integrity")
    assert integrity.status_code == 200
    assert integrity.json() == {"checked": 3, "valid": 3, "failures": []}


def test_tampered_artifact_is_reported_and_blocked(api_client: TestClient) -> None:
    created = api_client.post(
        "/api/v1/evaluations",
        json={
            "suite_path": "examples/suites/coding_repair.yaml",
            "agent_version": "baseline",
        },
    )
    assert created.status_code == 201
    run_id = created.json()["run_id"]
    store: ArtifactStore = api_client.app.state.store
    with psycopg.connect(store.database_url) as connection:
        connection.execute(
            sql.SQL(
                "UPDATE {}.evaluation_runs "
                "SET payload = jsonb_set(payload, '{{agent_version}}', %s::jsonb) "
                "WHERE run_id = %s"
            ).format(sql.Identifier(store.schema)),
            ('"tampered"', run_id),
        )

    report = api_client.get("/api/v1/integrity")
    assert report.status_code == 200
    assert report.json()["checked"] == 1
    assert report.json()["valid"] == 0
    assert report.json()["failures"][0]["artifact_id"] == run_id
    assert report.json()["failures"][0]["artifact_type"] == "run"

    blocked = api_client.get(f"/api/v1/runs/{run_id}")
    assert blocked.status_code == 409
    assert "failed SHA-256 integrity verification" in blocked.json()["detail"]


def test_guardrail_checks_become_tamper_evident_artifacts(
    api_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def configs(_client) -> list[GuardrailsConfig]:  # type: ignore[no-untyped-def]
        return [GuardrailsConfig(id="content_safety")]

    async def check(_client, **_kwargs) -> GuardrailEvidence:  # type: ignore[no-untyped-def]
        return GuardrailEvidence(
            config_id="content_safety",
            model="meta/llama-3.1-8b-instruct",
            submitted_text="<script>alert(1)</script>",
            response_text="I cannot help with that request.",
            passed_through=False,
            activated_rails=[{"name": "content safety check output"}],
            stats={"guardrail_generation_duration": 0.17},
        )

    client_type = type(api_client.app.state.guardrails_client)
    monkeypatch.setattr(client_type, "configs", configs)
    monkeypatch.setattr(client_type, "check", check)

    discovered = api_client.get("/api/v1/guardrails/configs")
    assert discovered.status_code == 200
    assert discovered.json() == [{"id": "content_safety"}]

    created = api_client.post(
        "/api/v1/guardrails/check",
        json={
            "model": "meta/llama-3.1-8b-instruct",
            "config_id": "content_safety",
            "input_text": "user request",
            "output_text": "candidate response",
        },
    )
    assert created.status_code == 201
    evidence_id = created.json()["evidence_id"]
    assert created.json()["evidence"]["passed_through"] is False
    assert created.json()["evidence"]["activated_rails"][0]["name"] == (
        "content safety check output"
    )

    listed = api_client.get("/api/v1/guardrails/evidence")
    assert listed.status_code == 200
    assert listed.json()[0]["evidence_id"] == evidence_id
    assert listed.json()[0]["config_id"] == "content_safety"
    assert api_client.get(f"/api/v1/guardrails/evidence/{evidence_id}").status_code == 200

    operations = api_client.get("/api/v1/operations").json()
    assert operations["guardrail_evidence_total"] == 1
    assert operations["guardrail_interventions_total"] == 1
    metrics = api_client.get("/metrics").text
    assert "aecontrol_guardrail_evidence_total 1" in metrics
    assert "aecontrol_guardrail_interventions_total 1" in metrics

    dashboard = api_client.get("/")
    assert dashboard.status_code == 200
    assert "Safety Evidence" in dashboard.text
    assert "Intervention rate<b>100.0%" in dashboard.text
    assert "content_safety" in dashboard.text
    detail = api_client.get(f"/guardrails/evidence/{evidence_id}")
    assert detail.status_code == 200
    assert "Guardrail Check" in detail.text
    assert "Intervention" in detail.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in detail.text
    assert "<script>alert(1)</script>" not in detail.text
    assert "I cannot help with that request." in detail.text
    assert "content safety check output" in detail.text

    integrity = api_client.get("/api/v1/integrity")
    assert integrity.json() == {"checked": 1, "valid": 1, "failures": []}

    store: ArtifactStore = api_client.app.state.store
    with psycopg.connect(store.database_url) as connection:
        connection.execute(
            sql.SQL(
                "UPDATE {}.guardrail_evidence "
                "SET payload = jsonb_set(payload, '{{evidence,response_text}}', %s::jsonb) "
                "WHERE evidence_id = %s"
            ).format(sql.Identifier(store.schema)),
            ('"tampered"', evidence_id),
        )

    report = api_client.get("/api/v1/integrity").json()
    assert report["valid"] == 0
    assert report["failures"][0]["artifact_type"] == "guardrail_evidence"
    blocked = api_client.get(f"/api/v1/guardrails/evidence/{evidence_id}")
    assert blocked.status_code == 409
    assert "failed SHA-256 integrity verification" in blocked.json()["detail"]
    browser_blocked = api_client.get(f"/guardrails/evidence/{evidence_id}")
    assert browser_blocked.status_code == 409
    assert api_client.get(f"/api/v1/guardrails/evidence/{uuid4()}").status_code == 404
    assert api_client.get(f"/guardrails/evidence/{uuid4()}").status_code == 404


def test_guardrail_upstream_errors_are_actionable(
    api_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def unavailable(_client, **_kwargs) -> GuardrailEvidence:  # type: ignore[no-untyped-def]
        raise GuardrailsError("NeMo Guardrails request failed: service unavailable")

    monkeypatch.setattr(type(api_client.app.state.guardrails_client), "check", unavailable)
    response = api_client.post(
        "/api/v1/guardrails/check",
        json={"model": "model", "config_id": "config", "input_text": "request"},
    )
    assert response.status_code == 502
    assert response.json()["detail"].endswith("service unavailable")


def test_api_returns_actionable_not_found_responses(api_client: TestClient) -> None:
    missing = api_client.get(f"/api/v1/runs/{uuid4()}")
    assert missing.status_code == 404
    assert missing.json() == {"detail": "run was not found"}

    bad_suite = api_client.post(
        "/api/v1/evaluations",
        json={"suite_path": "missing.yaml", "agent_version": "baseline"},
    )
    assert bad_suite.status_code == 422
    assert "suite file is not available under the allowed input root" in bad_suite.json()["detail"]

    outside_root = api_client.post(
        "/api/v1/evaluations",
        json={"suite_path": "/etc/passwd", "agent_version": "baseline"},
    )
    assert outside_root.status_code == 422
    assert outside_root.json() == {
        "detail": "suite file is not available under the allowed input root: /etc/passwd"
    }

    generated_id = api_client.get("/healthz", headers={"X-Request-ID": "invalid id!"})
    assert generated_id.headers["x-request-id"] != "invalid id!"


def test_durable_job_runs_to_completion(api_client: TestClient) -> None:
    parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    queued = api_client.post(
        "/api/v1/jobs",
        headers={"traceparent": parent, "X-Request-ID": "queue-request"},
        json={
            "suite_path": "examples/suites/coding_repair.yaml",
            "agent_version": "candidate_fixed",
            "priority": 10,
            "max_attempts": 2,
        },
    )
    assert queued.status_code == 202
    assert queued.json()["status"] == "queued"
    assert queued.json()["traceparent"].split("-")[1] == parent.split("-")[1]
    assert queued.json()["request_id"] == "queue-request"
    assert queued.headers["traceparent"] == queued.json()["traceparent"]

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

    compatible_job = store.enqueue_job("examples/suites/coding_repair.yaml", "openai/test-model")
    assert compatible_job.required_labels == {"runtime": "openai-compatible"}
    store.cancel_job(compatible_job.job_id)
    nim_job = store.enqueue_job("examples/suites/coding_repair.yaml", "nim/meta/llama-test")
    assert nim_job.required_labels == {"runtime": "nvidia-nim"}
    store.cancel_job(nim_job.job_id)


def test_gpu_resource_constraints_are_atomically_admitted(api_client: TestClient) -> None:
    store: ArtifactStore = api_client.app.state.store
    constrained = store.enqueue_job(
        "examples/suites/coding_repair.yaml",
        "baseline",
        required_accelerator=Accelerator.CUDA,
        minimum_gpu_memory_mb=12000,
        minimum_cuda_compute_capability=8.9,
    )
    base = WorkerCapabilities(
        hostname="gpu-host",
        operating_system="linux",
        architecture="x86_64",
        cpu_count=8,
        accelerators=[Accelerator.CPU, Accelerator.CUDA],
    )
    insufficient_memory = base.model_copy(
        update={
            "gpus": [GpuDevice(name="Small Ada", memory_total_mb=8192, compute_capability="8.9")]
        }
    )
    assert store.lease_job("small-worker", capabilities=insufficient_memory) is None
    assert store.get_job(constrained.job_id).attempts == 0

    insufficient_compute = base.model_copy(
        update={
            "gpus": [
                GpuDevice(
                    name="Large Older GPU",
                    memory_total_mb=16384,
                    compute_capability="8.0",
                )
            ]
        }
    )
    assert store.lease_job("older-worker", capabilities=insufficient_compute) is None
    assert store.get_job(constrained.job_id).attempts == 0

    split_resources = base.model_copy(
        update={
            "gpus": [
                GpuDevice(name="Fast Small", memory_total_mb=8192, compute_capability="9.0"),
                GpuDevice(name="Large Old", memory_total_mb=24576, compute_capability="8.0"),
            ]
        }
    )
    assert store.lease_job("split-worker", capabilities=split_resources) is None
    assert store.get_job(constrained.job_id).attempts == 0
    store.register_worker("split-worker", split_resources)
    blocked = api_client.get(f"/api/v1/jobs/{constrained.job_id}/placement")
    assert blocked.status_code == 200
    assert blocked.json()["schedulable"] is False
    assert blocked.json()["workers"][0]["reasons"] == [
        "no single GPU satisfies all memory and compute requirements"
    ]

    qualified = base.model_copy(
        update={
            "gpus": [
                GpuDevice(
                    name="RTX 5000 Ada",
                    memory_total_mb=16376,
                    compute_capability="8.9",
                )
            ]
        }
    )
    store.register_worker("qualified-worker", qualified)
    schedulable = api_client.get(f"/api/v1/jobs/{constrained.job_id}/placement")
    assert schedulable.status_code == 200
    assert schedulable.json()["schedulable"] is True
    assert schedulable.json()["matching_workers"] == 1
    claimed = store.lease_job("qualified-worker", capabilities=qualified)
    assert claimed is not None
    assert claimed.job_id == constrained.job_id
    assert claimed.attempts == 1
    store.cancel_job(constrained.job_id)

    invalid = api_client.post(
        "/api/v1/jobs",
        json={
            "suite_path": "examples/suites/coding_repair.yaml",
            "agent_version": "baseline",
            "minimum_gpu_memory_mb": 1000,
        },
    )
    assert invalid.status_code == 422
    assert "require the cuda accelerator" in invalid.json()["detail"]


def test_live_gpu_load_constraints_are_atomically_admitted(api_client: TestClient) -> None:
    store: ArtifactStore = api_client.app.state.store
    constrained = store.enqueue_job(
        "examples/suites/coding_repair.yaml",
        "baseline",
        required_accelerator=Accelerator.CUDA,
        minimum_gpu_memory_mb=16000,
        minimum_gpu_memory_available_mb=8000,
        maximum_gpu_utilization_percent=30,
    )
    base = WorkerCapabilities(
        hostname="gpu-host",
        operating_system="linux",
        architecture="x86_64",
        cpu_count=8,
        accelerators=[Accelerator.CPU, Accelerator.CUDA],
    )
    saturated = base.model_copy(
        update={
            "gpus": [
                GpuDevice(
                    name="Busy GPU",
                    memory_total_mb=24576,
                    memory_used_mb=20000,
                    utilization_percent=95,
                    compute_capability="8.9",
                )
            ]
        }
    )
    assert store.lease_job("busy-worker", capabilities=saturated) is None
    assert store.get_job(constrained.job_id).attempts == 0

    missing = base.model_copy(
        update={
            "gpus": [
                GpuDevice(name="Unknown Load", memory_total_mb=24576, compute_capability="8.9")
            ]
        }
    )
    store.register_worker("unknown-worker", missing)
    diagnostic = api_client.get(f"/api/v1/jobs/{constrained.job_id}/placement").json()
    assert diagnostic["workers"][0]["reasons"] == [
        "GPU free-memory telemetry is unavailable",
        "GPU utilization telemetry is unavailable",
    ]

    split = base.model_copy(
        update={
            "gpus": [
                GpuDevice(
                    name="Free but Busy",
                    memory_total_mb=24576,
                    memory_used_mb=1000,
                    utilization_percent=90,
                    compute_capability="8.9",
                ),
                GpuDevice(
                    name="Idle but Full",
                    memory_total_mb=24576,
                    memory_used_mb=20000,
                    utilization_percent=5,
                    compute_capability="8.9",
                ),
            ]
        }
    )
    assert store.lease_job("split-load-worker", capabilities=split) is None

    available = base.model_copy(
        update={
            "gpus": [
                GpuDevice(
                    name="Available GPU",
                    memory_total_mb=24576,
                    memory_used_mb=4096,
                    utilization_percent=20,
                    compute_capability="8.9",
                )
            ]
        }
    )
    claimed = store.lease_job("available-worker", capabilities=available)
    assert claimed is not None
    assert claimed.job_id == constrained.job_id
    assert claimed.minimum_gpu_memory_available_mb == 8000
    assert claimed.maximum_gpu_utilization_percent == 30

    invalid = api_client.post(
        "/api/v1/jobs",
        json={
            "suite_path": "examples/suites/coding_repair.yaml",
            "agent_version": "baseline",
            "maximum_gpu_utilization_percent": 20,
        },
    )
    assert invalid.status_code == 422
    assert "require the cuda accelerator" in invalid.json()["detail"]


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
