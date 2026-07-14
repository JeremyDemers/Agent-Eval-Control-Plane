from __future__ import annotations

import asyncio
import base64
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import make_conninfo

from aecontrol.api import DEFAULT_DATABASE_URL, create_app
from aecontrol.auth import hash_api_key
from aecontrol.checkpoints import FileCheckpointSink, SignedLedgerCheckpoint, verify_checkpoint
from aecontrol.database import DatabaseRuntimeConfiguration
from aecontrol.federation import FederatedIdentity, FederationError
from aecontrol.guardrails import GuardrailEvidence, GuardrailsConfig, GuardrailsError
from aecontrol.integrity import ED25519, HMAC_SHA256, ArtifactKeyring, generate_ed25519_keypair
from aecontrol.jobs import EvaluationWorker
from aecontrol.models import Accelerator, GpuDevice, JobStatus, WorkerCapabilities
from aecontrol.store import ArtifactStore
from aecontrol.tenancy import bind_tenant, reset_tenant


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


@pytest.mark.parametrize("stored_version", [1, 10, 14, 15, 16])
def test_supported_schema_is_migrated_in_place(database_url: str, stored_version: int) -> None:
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
                sql.SQL("INSERT INTO {}.schema_metadata(version) VALUES (%s)").format(
                    sql.Identifier(schema)
                ),
                (stored_version,),
            )

        store = ArtifactStore(database_url, schema=schema)
        assert store.health()["schema_version"] == 17
    finally:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_pooled_api_lifecycle_serves_concurrent_health_checks(database_url: str) -> None:
    schema = f"test_{uuid4().hex}"
    configuration = DatabaseRuntimeConfiguration(
        pool_min_size=1,
        pool_max_size=3,
        pool_timeout_seconds=2,
        pool_max_waiting=10,
    )
    store: ArtifactStore | None = None
    try:
        with TestClient(
            create_app(database_url, schema=schema, database_config=configuration)
        ) as client:
            store = client.app.state.store
            with ThreadPoolExecutor(max_workers=6) as executor:
                responses = list(executor.map(lambda _: client.get("/healthz"), range(12)))
            assert all(response.status_code == 200 for response in responses)
            assert all(response.json()["connection_mode"] == "pooled" for response in responses)
            metrics = client.get("/metrics")
            assert metrics.status_code == 200
            assert 'aecontrol_database_pool_limit{bound="maximum"} 3' in metrics.text
            assert "aecontrol_database_pool_waiting_requests" in metrics.text
            assert store.closed is False
        assert store.closed is True
        with pytest.raises(RuntimeError, match="artifact store is closed"):
            store.health()
    finally:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_schema_initialization_waits_for_database_advisory_lock(database_url: str) -> None:
    schema = f"test_{uuid4().hex}"
    store = ArtifactStore(
        database_url,
        schema=schema,
        database_config=DatabaseRuntimeConfiguration(migration_lock_timeout_seconds=2),
    )
    try:
        with (
            psycopg.connect(database_url) as blocker,
            ThreadPoolExecutor(max_workers=1) as executor,
        ):
            blocker.execute("SELECT pg_advisory_xact_lock(%s)", (store._migration_lock_key(),))
            initialization = executor.submit(store.initialize)
            time.sleep(0.1)
            assert initialization.done() is False
            blocker.commit()
            initialization.result(timeout=2)
        assert store.health()["connection_mode"] == "direct"
    finally:
        store.close()
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
        f"  - key_id: administrator\n    secret_sha256: {hash_api_key('admin-secret')}\n"
        "    scopes: [admin]\n"
    )
    try:
        with TestClient(create_app(database_url, schema=schema, auth_config=auth_config)) as client:
            assert client.get("/healthz").status_code == 200
            assert client.get("/").status_code == 200

            missing = client.get("/api/v1/runs")
            assert missing.status_code == 401
            assert missing.headers["www-authenticate"] == "Bearer"
            assert missing.json() == {"detail": "Bearer credential is required"}

            invalid = client.get("/api/v1/runs", headers={"Authorization": "Bearer wrong-secret"})
            assert invalid.status_code == 401
            assert invalid.json() == {"detail": "Bearer credential is invalid"}

            observer_headers = {"Authorization": "Bearer read-secret"}
            observed = client.get("/api/v1/runs", headers=observer_headers)
            assert observed.status_code == 200
            assert observed.headers["x-aecontrol-tenant"] == "default"
            forbidden = client.post(
                "/api/v1/jobs",
                headers=observer_headers,
                json={
                    "suite_path": "examples/suites/coding_repair.yaml",
                    "agent_version": "baseline",
                },
            )
            assert forbidden.status_code == 403
            assert forbidden.json() == {"detail": "Bearer credential requires the write scope"}

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

            forbidden_config = client.post(
                "/api/v1/guardrails/config-versions",
                headers=operator_headers,
                json={
                    "config_id": "content_safety",
                    "version": "1.0.0",
                    "bundle_sha256": "a" * 64,
                },
            )
            assert forbidden_config.status_code == 403
            assert forbidden_config.json() == {
                "detail": "Bearer credential requires the admin scope"
            }

            admin_config = client.post(
                "/api/v1/guardrails/config-versions",
                headers={"Authorization": "Bearer admin-secret"},
                json={
                    "config_id": "content_safety",
                    "version": "1.0.0",
                    "bundle_sha256": "a" * 64,
                },
            )
            assert admin_config.status_code == 201
            assert admin_config.json()["created_by"] == "administrator"

            security = client.get("/openapi.json").json()["components"]["securitySchemes"]
            assert security["ControlPlaneAPIKey"]["scheme"] == "bearer"
    finally:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_oidc_federation_preserves_tenant_scope_and_suspension(database_url: str, tmp_path) -> None:  # type: ignore[no-untyped-def]
    schema = f"test_{uuid4().hex}"
    auth_config = tmp_path / "federation-auth.yaml"
    auth_config.write_text(
        "keys:\n"
        f"  - key_id: platform-operator\n    tenant_id: control-plane\n"
        f"    secret_sha256: {hash_api_key('operator-secret')}\n    scopes: [operator]\n"
    )
    identities = {
        "read.token.signature": FederatedIdentity(
            principal_id="oidc:" + "a" * 20,
            tenant_id="research",
            scopes={"read"},
        ),
        "admin.token.signature": FederatedIdentity(
            principal_id="oidc:" + "b" * 20,
            tenant_id="research",
            scopes={"admin"},
        ),
    }

    class Verifier:
        def verify(self, token: str) -> FederatedIdentity:
            try:
                return identities[token]
            except KeyError as error:
                raise FederationError("invalid token") from error

    operator = {"Authorization": "Bearer operator-secret"}
    reader = {"Authorization": "Bearer read.token.signature"}
    administrator = {"Authorization": "Bearer admin.token.signature"}
    try:
        with TestClient(
            create_app(
                database_url,
                schema=schema,
                auth_config=auth_config,
                federated_token_verifier=Verifier(),
            )
        ) as client:
            created = client.post(
                "/api/v1/platform/tenants",
                headers=operator,
                json={"tenant_id": "research", "display_name": "Federated Research"},
            )
            assert created.status_code == 201

            observed = client.get("/api/v1/runs", headers=reader)
            assert observed.status_code == 200
            assert observed.headers["x-aecontrol-tenant"] == "research"
            assert (
                client.post(
                    "/api/v1/jobs",
                    headers=reader,
                    json={
                        "suite_path": "examples/suites/coding_repair.yaml",
                        "agent_version": "baseline",
                    },
                ).status_code
                == 403
            )
            assert client.get("/api/v1/tenant/quota", headers=administrator).status_code == 200
            assert client.get("/api/v1/platform/tenants", headers=administrator).status_code == 403

            registered = client.post(
                "/api/v1/guardrails/config-versions",
                headers=administrator,
                json={
                    "config_id": "federated-safety",
                    "version": "1.0.0",
                    "bundle_sha256": "a" * 64,
                },
            )
            assert registered.status_code == 201
            assert registered.json()["created_by"] == "oidc:" + "b" * 20

            invalid = client.get(
                "/api/v1/runs", headers={"Authorization": "Bearer bad.token.signature"}
            )
            assert invalid.status_code == 401
            assert invalid.json() == {"detail": "Bearer credential is invalid"}

            suspended = client.patch(
                "/api/v1/platform/tenants/research",
                headers=operator,
                json={"status": "suspended"},
            )
            assert suspended.status_code == 200
            assert client.get("/api/v1/runs", headers=reader).status_code == 401
            assert client.get("/api/v1/runs", headers=administrator).status_code == 401
    finally:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_oidc_federation_can_enable_authentication_without_key_config(database_url: str) -> None:
    schema = f"test_{uuid4().hex}"

    class Verifier:
        def verify(self, token: str) -> FederatedIdentity:
            if token != "valid.token.signature":
                raise FederationError("invalid token")
            return FederatedIdentity(
                principal_id="oidc:" + "c" * 20,
                tenant_id="default",
                scopes={"read"},
            )

    try:
        with TestClient(
            create_app(database_url, schema=schema, federated_token_verifier=Verifier())
        ) as client:
            assert client.get("/api/v1/runs").status_code == 401
            accepted = client.get(
                "/api/v1/runs",
                headers={"Authorization": "Bearer valid.token.signature"},
            )
            assert accepted.status_code == 200
            assert accepted.headers["x-aecontrol-tenant"] == "default"
            assert (
                client.get(
                    "/api/v1/runs",
                    headers={"Authorization": "Bearer opaque-invalid-key"},
                ).status_code
                == 401
            )
    finally:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_local_trust_uses_deployment_tenant(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    schema = f"test_{uuid4().hex}"
    monkeypatch.setenv("AECONTROL_TENANT_ID", "deployment-a")
    try:
        with TestClient(create_app(database_url, schema=schema)) as client:
            response = client.get("/api/v1/jobs")
            assert response.status_code == 200
            assert response.headers["x-aecontrol-tenant"] == "deployment-a"
    finally:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_self_service_tenant_lifecycle_and_key_rotation(database_url: str, tmp_path) -> None:  # type: ignore[no-untyped-def]
    schema = f"test_{uuid4().hex}"
    auth_config = tmp_path / "operator-auth.yaml"
    auth_config.write_text(
        "keys:\n"
        f"  - key_id: platform-operator\n    tenant_id: control-plane\n"
        f"    secret_sha256: {hash_api_key('operator-secret')}\n    scopes: [operator]\n"
        f"  - key_id: static-research-auditor\n    tenant_id: research\n"
        f"    secret_sha256: {hash_api_key('static-research-secret')}\n    scopes: [read]\n"
    )
    operator = {"Authorization": "Bearer operator-secret"}
    static_auditor = {"Authorization": "Bearer static-research-secret"}
    try:
        with TestClient(create_app(database_url, schema=schema, auth_config=auth_config)) as client:
            assert client.get("/api/v1/runs", headers=static_auditor).status_code == 200
            created = client.post(
                "/api/v1/platform/tenants",
                headers=operator,
                json={
                    "tenant_id": "research",
                    "display_name": "NVIDIA Agent Research",
                    "initial_key_id": "research-admin-v1",
                },
            )
            assert created.status_code == 201
            assert created.headers["cache-control"] == "no-store"
            issued = created.json()
            assert issued["tenant"]["status"] == "active"
            assert issued["key"]["scopes"] == ["admin"]
            assert "secret_sha256" not in issued["key"]
            initial_secret = issued["secret"]
            assert len(initial_secret) >= 32
            initial_admin = {"Authorization": f"Bearer {initial_secret}"}

            duplicate = client.post(
                "/api/v1/platform/tenants",
                headers=operator,
                json={"tenant_id": "research", "display_name": "Duplicate"},
            )
            assert duplicate.status_code == 409

            tenants = client.get("/api/v1/platform/tenants", headers=operator)
            assert [tenant["tenant_id"] for tenant in tenants.json()] == ["research"]
            assert client.get("/api/v1/platform/tenants", headers=initial_admin).status_code == 403

            current = client.get("/api/v1/tenant", headers=initial_admin)
            assert current.status_code == 200
            assert current.headers["x-aecontrol-tenant"] == "research"
            assert current.json()["display_name"] == "NVIDIA Agent Research"
            assert client.get("/api/v1/runs", headers=static_auditor).status_code == 200

            observer = client.post(
                "/api/v1/tenant/api-keys",
                headers=initial_admin,
                json={"key_id": "auditor", "scopes": ["read"]},
            )
            assert observer.status_code == 201
            assert observer.headers["cache-control"] == "no-store"
            observer_secret = observer.json()["secret"]
            observer_headers = {"Authorization": f"Bearer {observer_secret}"}
            assert client.get("/api/v1/runs", headers=observer_headers).status_code == 200
            assert (
                client.get("/api/v1/tenant/api-keys", headers=observer_headers).status_code == 403
            )

            final_admin = client.delete(
                "/api/v1/tenant/api-keys/research-admin-v1", headers=initial_admin
            )
            assert final_admin.status_code == 409
            assert "last active admin" in final_admin.json()["detail"]

            replacement = client.post(
                "/api/v1/tenant/api-keys",
                headers=initial_admin,
                json={"key_id": "research-admin-v2", "scopes": ["admin"]},
            )
            replacement_secret = replacement.json()["secret"]
            replacement_admin = {"Authorization": f"Bearer {replacement_secret}"}
            revoked = client.delete(
                "/api/v1/tenant/api-keys/research-admin-v1", headers=initial_admin
            )
            assert revoked.status_code == 200
            assert revoked.json()["revoked_by"] == "research-admin-v1"
            assert client.get("/api/v1/tenant", headers=initial_admin).status_code == 401
            assert client.get("/api/v1/tenant", headers=replacement_admin).status_code == 200

            suspended = client.patch(
                "/api/v1/platform/tenants/research",
                headers=operator,
                json={"status": "suspended"},
            )
            assert suspended.status_code == 200
            assert suspended.json()["status"] == "suspended"
            assert client.get("/api/v1/tenant", headers=replacement_admin).status_code == 401
            assert client.get("/api/v1/runs", headers=observer_headers).status_code == 401
            assert client.get("/api/v1/runs", headers=static_auditor).status_code == 401

            reactivated = client.patch(
                "/api/v1/platform/tenants/research",
                headers=operator,
                json={"status": "active"},
            )
            assert reactivated.status_code == 200
            assert client.get("/api/v1/runs", headers=static_auditor).status_code == 200
            keys = client.get("/api/v1/tenant/api-keys", headers=replacement_admin)
            assert keys.status_code == 200
            assert [key["key_id"] for key in keys.json()] == [
                "research-admin-v1",
                "auditor",
                "research-admin-v2",
            ]
            assert keys.json()[0]["revoked_at"] is not None
    finally:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_tenant_quotas_enforce_submission_and_concurrent_leases(
    database_url: str, tmp_path
) -> None:  # type: ignore[no-untyped-def]
    schema = f"test_{uuid4().hex}"
    auth_config = tmp_path / "quota-auth.yaml"
    auth_config.write_text(
        "keys:\n"
        f"  - key_id: platform-operator\n    tenant_id: control-plane\n"
        f"    secret_sha256: {hash_api_key('operator-secret')}\n    scopes: [operator]\n"
    )
    operator = {"Authorization": "Bearer operator-secret"}
    suite = "examples/suites/coding_repair.yaml"
    try:
        with TestClient(create_app(database_url, schema=schema, auth_config=auth_config)) as client:
            created = client.post(
                "/api/v1/platform/tenants",
                headers=operator,
                json={"tenant_id": "research", "display_name": "GPU Research"},
            )
            assert created.status_code == 201
            tenant = {"Authorization": f"Bearer {created.json()['secret']}"}

            configured = client.put(
                "/api/v1/platform/tenants/research/quota",
                headers=operator,
                json={
                    "max_queued_jobs": 1,
                    "max_jobs_per_hour": 2,
                    "max_running_jobs": 1,
                    "max_running_cuda_jobs": 0,
                },
            )
            assert configured.status_code == 200
            assert configured.json()["updated_by"] == "platform-operator"
            assert (
                client.put(
                    "/api/v1/platform/tenants/research/quota",
                    headers=tenant,
                    json={},
                ).status_code
                == 403
            )

            first = client.post(
                "/api/v1/jobs",
                headers=tenant,
                json={"suite_path": suite, "agent_version": "baseline"},
            )
            assert first.status_code == 202
            queue_blocked = client.post(
                "/api/v1/jobs",
                headers=tenant,
                json={"suite_path": suite, "agent_version": "baseline"},
            )
            assert queue_blocked.status_code == 429
            assert queue_blocked.json()["detail"] == {
                "code": "tenant_quota_exceeded",
                "quota": "max_queued_jobs",
                "limit": 1,
                "observed": 2,
            }

            assert (
                client.delete(f"/api/v1/jobs/{first.json()['job_id']}", headers=tenant).status_code
                == 200
            )
            second = client.post(
                "/api/v1/jobs",
                headers=tenant,
                json={"suite_path": suite, "agent_version": "baseline"},
            )
            assert second.status_code == 202
            assert (
                client.delete(f"/api/v1/jobs/{second.json()['job_id']}", headers=tenant).status_code
                == 200
            )
            hourly_blocked = client.post(
                "/api/v1/jobs",
                headers=tenant,
                json={"suite_path": suite, "agent_version": "baseline"},
            )
            assert hourly_blocked.status_code == 429
            assert hourly_blocked.json()["detail"]["quota"] == "max_jobs_per_hour"

            relaxed = client.put(
                "/api/v1/platform/tenants/research/quota",
                headers=operator,
                json={
                    "max_queued_jobs": 10,
                    "max_jobs_per_hour": 100,
                    "max_running_jobs": 1,
                    "max_running_cuda_jobs": 1,
                },
            )
            assert relaxed.status_code == 200
            for _ in range(2):
                assert (
                    client.post(
                        "/api/v1/jobs",
                        headers=tenant,
                        json={"suite_path": suite, "agent_version": "baseline"},
                    ).status_code
                    == 202
                )

            store = client.app.state.store
            capabilities = WorkerCapabilities(
                hostname="quota-worker",
                operating_system="linux",
                architecture="x86_64",
                cpu_count=8,
                accelerators=[Accelerator.CPU],
            )

            def lease(worker_id: str):  # type: ignore[no-untyped-def]
                token = bind_tenant("research")
                try:
                    return store.lease_job(worker_id, capabilities=capabilities)
                finally:
                    reset_tenant(token)

            with ThreadPoolExecutor(max_workers=2) as executor:
                leased = list(executor.map(lease, ("worker-a", "worker-b")))
            assert sum(job is not None for job in leased) == 1

            quota_status = client.get("/api/v1/tenant/quota", headers=tenant)
            assert quota_status.status_code == 200
            assert quota_status.json()["usage"]["active_running_jobs"] == 1
            assert quota_status.json()["usage"]["queued_jobs"] == 1
            assert (
                client.get("/api/v1/platform/tenants/research/quota", headers=operator).json()[
                    "max_running_jobs"
                ]
                == 1
            )

            for job in client.get("/api/v1/jobs", headers=tenant).json():
                if job["status"] in {"queued", "running"}:
                    assert (
                        client.delete(f"/api/v1/jobs/{job['job_id']}", headers=tenant).status_code
                        == 200
                    )
            assert (
                client.put(
                    "/api/v1/platform/tenants/research/quota",
                    headers=operator,
                    json={
                        "max_queued_jobs": 10,
                        "max_jobs_per_hour": 100,
                        "max_running_jobs": 2,
                        "max_running_cuda_jobs": 1,
                    },
                ).status_code
                == 200
            )
            for accelerator, priority in (("cuda", 10), ("cuda", 9), ("cpu", 0)):
                assert (
                    client.post(
                        "/api/v1/jobs",
                        headers=tenant,
                        json={
                            "suite_path": suite,
                            "agent_version": "baseline",
                            "required_accelerator": accelerator,
                            "priority": priority,
                        },
                    ).status_code
                    == 202
                )

            cuda_capabilities = WorkerCapabilities(
                hostname="mixed-worker",
                operating_system="linux",
                architecture="x86_64",
                cpu_count=8,
                accelerators=[Accelerator.CPU, Accelerator.CUDA],
                gpus=[
                    GpuDevice(
                        name="NVIDIA L4",
                        memory_total_mb=24_000,
                        compute_capability="8.9",
                    )
                ],
            )
            token = bind_tenant("research")
            try:
                first_mixed = store.lease_job("mixed-a", capabilities=cuda_capabilities)
                second_mixed = store.lease_job("mixed-b", capabilities=cuda_capabilities)
                third_mixed = store.lease_job("mixed-c", capabilities=cuda_capabilities)
            finally:
                reset_tenant(token)
            assert first_mixed is not None
            assert first_mixed.required_accelerator == Accelerator.CUDA
            assert second_mixed is not None
            assert second_mixed.required_accelerator == Accelerator.CPU
            assert third_mixed is None
    finally:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_api_keys_enforce_postgres_tenant_isolation(database_url: str, tmp_path) -> None:  # type: ignore[no-untyped-def]
    schema = f"test_{uuid4().hex}"
    role = f"tenant_test_{uuid4().hex}"
    role_password = uuid4().hex
    auth_config = tmp_path / "tenant-auth.yaml"
    auth_config.write_text(
        "keys:\n"
        f"  - key_id: alpha-admin\n    tenant_id: alpha\n"
        f"    secret_sha256: {hash_api_key('alpha-secret')}\n    scopes: [admin]\n"
        f"  - key_id: beta-admin\n    tenant_id: beta\n"
        f"    secret_sha256: {hash_api_key('beta-secret')}\n    scopes: [admin]\n"
    )
    with psycopg.connect(database_url, autocommit=True) as connection:
        database = connection.info.dbname
        connection.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                sql.Identifier(role), sql.Literal(role_password)
            )
        )
        connection.execute(
            sql.SQL("GRANT CREATE ON DATABASE {} TO {}").format(
                sql.Identifier(database), sql.Identifier(role)
            )
        )

    tenant_database_url = make_conninfo(database_url, user=role, password=role_password)
    configuration = DatabaseRuntimeConfiguration(
        pool_min_size=1,
        pool_max_size=1,
        pool_timeout_seconds=2,
        pool_max_waiting=5,
    )
    try:
        with TestClient(
            create_app(
                tenant_database_url,
                schema=schema,
                auth_config=auth_config,
                database_config=configuration,
            )
        ) as client:
            alpha = {"Authorization": "Bearer alpha-secret"}
            beta = {"Authorization": "Bearer beta-secret"}
            queued = client.post(
                "/api/v1/jobs",
                headers=alpha,
                json={
                    "suite_path": "examples/suites/coding_repair.yaml",
                    "agent_version": "baseline",
                },
            )
            assert queued.status_code == 202
            assert queued.headers["x-aecontrol-tenant"] == "alpha"
            job_id = queued.json()["job_id"]

            alpha_jobs = client.get("/api/v1/jobs", headers=alpha)
            beta_jobs = client.get("/api/v1/jobs", headers=beta)
            assert [item["job_id"] for item in alpha_jobs.json()] == [job_id]
            assert beta_jobs.json() == []
            assert client.get(f"/api/v1/jobs/{job_id}", headers=beta).status_code == 404

            for headers, digest in ((alpha, "a" * 64), (beta, "b" * 64)):
                registered = client.post(
                    "/api/v1/guardrails/config-versions",
                    headers=headers,
                    json={
                        "config_id": "shared-policy-name",
                        "version": "1.0.0",
                        "bundle_sha256": digest,
                    },
                )
                assert registered.status_code == 201
                visible = client.get("/api/v1/guardrails/config-versions", headers=headers)
                assert [item["bundle_sha256"] for item in visible.json()] == [digest]

            for headers, agent_version in ((alpha, "baseline"), (beta, "candidate_fixed")):
                evaluated = client.post(
                    "/api/v1/evaluations",
                    headers=headers,
                    json={
                        "suite_path": "examples/suites/coding_repair.yaml",
                        "agent_version": agent_version,
                    },
                )
                assert evaluated.status_code == 201

        with psycopg.connect(database_url) as connection:
            connection.execute(
                sql.SQL(
                    "ALTER TABLE {}.artifact_ledger DISABLE TRIGGER artifact_ledger_append_only"
                ).format(sql.Identifier(schema))
            )
            connection.execute(
                sql.SQL("DELETE FROM {}.artifact_ledger").format(sql.Identifier(schema))
            )
            connection.execute(
                sql.SQL("UPDATE {}.schema_metadata SET version = 13").format(sql.Identifier(schema))
            )

        migrated = ArtifactStore(tenant_database_url, schema=schema)
        assert migrated.health()["schema_version"] == 17

        with psycopg.connect(database_url) as connection:
            ledger_tenants = connection.execute(
                sql.SQL(
                    "SELECT tenant_id, count(*) FROM {}.artifact_ledger "
                    "GROUP BY tenant_id ORDER BY tenant_id"
                ).format(sql.Identifier(schema))
            ).fetchall()
            assert ledger_tenants == [("alpha", 1), ("beta", 1)]
            isolated_tables = connection.execute(
                """SELECT count(*) AS value
                   FROM pg_class AS class
                   JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
                   WHERE namespace.nspname = %s
                     AND class.relname = ANY(%s)
                     AND class.relrowsecurity
                     AND class.relforcerowsecurity""",
                (
                    schema,
                    [
                        "evaluation_runs",
                        "comparisons",
                        "guardrail_evidence",
                        "guardrail_config_versions",
                        "guardrail_config_activations",
                        "evaluation_jobs",
                        "workers",
                        "artifact_ledger",
                        "ledger_checkpoints",
                    ],
                ),
            ).fetchone()
            assert isolated_tables is not None
            assert isolated_tables[0] == 9
    finally:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )
            connection.execute(
                sql.SQL("REVOKE CREATE ON DATABASE {} FROM {}").format(
                    sql.Identifier(connection.info.dbname), sql.Identifier(role)
                )
            )
            connection.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


def test_persisted_evaluation_comparison_and_trace_flow(api_client: TestClient) -> None:
    health = api_client.get("/healthz", headers={"X-Request-ID": "integration-request"})
    assert health.status_code == 200
    assert health.json()["schema_version"] == 17
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
    integrity_payload = integrity.json()
    assert len(integrity_payload.pop("ledger_head_sha256")) == 64
    assert integrity_payload == {
        "checked": 3,
        "valid": 3,
        "signed": 0,
        "unsigned": 3,
        "signature_algorithms": {},
        "ledger_checked": 3,
        "ledger_valid": 3,
        "ledger_failures": [],
        "checkpoint_checked": 0,
        "checkpoint_valid": 0,
        "checkpoint_failures": [],
        "failures": [],
    }


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


def test_signed_artifacts_support_rotation_and_fail_closed(database_url: str) -> None:
    schema = f"test_{uuid4().hex}"
    old_keyring = ArtifactKeyring({"old": b"o" * 32}, "old")
    rotated_keyring = ArtifactKeyring({"old": b"o" * 32, "new": b"n" * 32}, "new")
    try:
        with TestClient(
            create_app(database_url, schema=schema, artifact_keyring=old_keyring)
        ) as client:
            old = client.post(
                "/api/v1/evaluations",
                json={
                    "suite_path": "examples/suites/coding_repair.yaml",
                    "agent_version": "baseline",
                },
            )
            assert old.status_code == 201
            old_run_id = old.json()["run_id"]
            report = client.get("/api/v1/integrity").json()
            assert report["signed"] == 1
            assert report["unsigned"] == 0
            assert report["valid"] == 1

        with psycopg.connect(database_url) as connection:
            connection.execute(
                sql.SQL(
                    "UPDATE {}.evaluation_runs "
                    "SET signature_hmac_sha256 = signature_value, "
                    "signature_algorithm = NULL, signature_value = NULL "
                    "WHERE run_id = %s"
                ).format(sql.Identifier(schema)),
                (old_run_id,),
            )
            connection.execute(
                sql.SQL("UPDATE {}.schema_metadata SET version = 12").format(sql.Identifier(schema))
            )

        with TestClient(
            create_app(database_url, schema=schema, artifact_keyring=rotated_keyring)
        ) as client:
            assert client.get(f"/api/v1/runs/{old_run_id}").status_code == 200
            new = client.post(
                "/api/v1/evaluations",
                json={
                    "suite_path": "examples/suites/coding_repair.yaml",
                    "agent_version": "candidate_fixed",
                },
            )
            assert new.status_code == 201
            new_run_id = new.json()["run_id"]
            report = client.get("/api/v1/integrity").json()
            assert report["signed"] == 2
            assert report["unsigned"] == 0
            assert report["valid"] == 2
            assert report["signature_algorithms"] == {HMAC_SHA256: 2}

        with psycopg.connect(database_url) as connection:
            rows = connection.execute(
                sql.SQL(
                    "SELECT run_id, signature_algorithm, signature_key_id, signature_value "
                    "FROM {}.evaluation_runs ORDER BY completed_at"
                ).format(sql.Identifier(schema))
            ).fetchall()
        assert [(str(row[0]), row[1], row[2]) for row in rows] == [
            (old_run_id, HMAC_SHA256, "old"),
            (new_run_id, HMAC_SHA256, "new"),
        ]
        assert all(len(row[3]) == 64 for row in rows)
        assert all(row[3] not in {"o" * 32, "n" * 32} for row in rows)

        missing_old_keyring = ArtifactKeyring({"new": b"n" * 32}, "new")
        with TestClient(
            create_app(database_url, schema=schema, artifact_keyring=missing_old_keyring)
        ) as client:
            blocked = client.get(f"/api/v1/runs/{old_run_id}")
            assert blocked.status_code == 409
            assert (
                "requires unavailable artifact verification key 'old'" in blocked.json()["detail"]
            )
            report = client.get("/api/v1/integrity").json()
            assert report["valid"] == 1
            assert report["failures"][0]["failure_kind"] == "missing_signing_key"
            assert report["failures"][0]["signature_algorithm"] == HMAC_SHA256
            assert report["failures"][0]["signing_key_id"] == "old"

        with psycopg.connect(database_url) as connection:
            connection.execute(
                sql.SQL(
                    "UPDATE {}.evaluation_runs SET signature_value = %s WHERE run_id = %s"
                ).format(sql.Identifier(schema)),
                ("0" * 64, new_run_id),
            )
        with TestClient(
            create_app(database_url, schema=schema, artifact_keyring=rotated_keyring)
        ) as client:
            blocked = client.get(f"/api/v1/runs/{new_run_id}")
            assert blocked.status_code == 409
            assert "failed hmac-sha256 authenticity verification" in blocked.json()["detail"]
            report = client.get("/api/v1/integrity").json()
            assert report["valid"] == 1
            assert report["failures"][0]["failure_kind"] == "signature"
            assert report["failures"][0]["signing_key_id"] == "new"
    finally:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_artifact_ledger_is_append_only_and_detects_source_deletion(
    api_client: TestClient,
) -> None:
    run_ids: list[str] = []
    for agent_version in ("baseline", "candidate_fixed"):
        created = api_client.post(
            "/api/v1/evaluations",
            json={
                "suite_path": "examples/suites/coding_repair.yaml",
                "agent_version": agent_version,
            },
        )
        assert created.status_code == 201
        run_ids.append(created.json()["run_id"])

    report = api_client.get("/api/v1/integrity").json()
    assert report["ledger_checked"] == 2
    assert report["ledger_valid"] == 2
    assert report["ledger_failures"] == []
    assert len(report["ledger_head_sha256"]) == 64

    store: ArtifactStore = api_client.app.state.store
    with (
        pytest.raises(psycopg.Error, match="artifact ledger is append-only"),
        psycopg.connect(store.database_url) as connection,
    ):
        connection.execute(
            sql.SQL("DELETE FROM {}.artifact_ledger WHERE sequence = 1").format(
                sql.Identifier(store.schema)
            )
        )
    with (
        pytest.raises(psycopg.Error, match="artifact ledger is append-only"),
        psycopg.connect(store.database_url) as connection,
    ):
        connection.execute(
            sql.SQL("UPDATE {}.artifact_ledger SET entry_sha256 = %s WHERE sequence = 1").format(
                sql.Identifier(store.schema)
            ),
            ("f" * 64,),
        )

    with psycopg.connect(store.database_url) as connection:
        connection.execute(
            sql.SQL("DELETE FROM {}.evaluation_runs WHERE run_id = %s").format(
                sql.Identifier(store.schema)
            ),
            (run_ids[0],),
        )

    damaged = api_client.get("/api/v1/integrity").json()
    assert damaged["checked"] == 1
    assert damaged["valid"] == 1
    assert damaged["ledger_checked"] == 2
    assert damaged["ledger_valid"] == 1
    assert damaged["ledger_failures"] == [
        {
            "sequence": 1,
            "artifact_type": "run",
            "artifact_id": run_ids[0],
            "reason": "missing_artifact",
            "expected_sha256": None,
            "actual_sha256": None,
        }
    ]


def test_checkpoint_publication_requires_external_sink(api_client: TestClient) -> None:
    response = api_client.post("/api/v1/integrity/checkpoints", json={"retention_days": 30})

    assert response.status_code == 503
    assert response.json() == {"detail": "checkpoint publisher is not configured"}


def test_signed_ledger_checkpoint_is_persisted_published_and_append_only(
    database_url: str, tmp_path
) -> None:  # type: ignore[no-untyped-def]
    schema = f"test_{uuid4().hex}"
    private_key, public_key = generate_ed25519_keypair()
    signer = ArtifactKeyring(
        active_key_id="checkpoint-attestor",
        active_algorithm=ED25519,
        ed25519_private_keys={"checkpoint-attestor": private_key},
    )
    verifier = ArtifactKeyring(ed25519_public_keys={"checkpoint-attestor": public_key})
    sink = FileCheckpointSink(tmp_path / "checkpoints")
    try:
        with TestClient(
            create_app(
                database_url,
                schema=schema,
                artifact_keyring=signer,
                checkpoint_sink=sink,
            )
        ) as client:
            created = client.post(
                "/api/v1/evaluations",
                json={
                    "suite_path": "examples/suites/coding_repair.yaml",
                    "agent_version": "candidate_fixed",
                },
            )
            assert created.status_code == 201

            published = client.post("/api/v1/integrity/checkpoints", json={"retention_days": 90})
            assert published.status_code == 201
            publication = published.json()
            checkpoint = SignedLedgerCheckpoint.model_validate(publication["checkpoint"])
            assert checkpoint.payload.ledger_sequence == 1
            assert checkpoint.payload.ledger_entries == 1
            assert (
                checkpoint.payload.ledger_head_sha256
                == client.get("/api/v1/integrity").json()["ledger_head_sha256"]
            )
            assert verify_checkpoint(checkpoint, verifier) is True
            assert publication["destination"].startswith(str(tmp_path))
            assert (tmp_path / "checkpoints" / publication["object_key"]).read_bytes() == (
                checkpoint.canonical_bytes()
            )

            repeated = client.post("/api/v1/integrity/checkpoints", json={"retention_days": 30})
            assert repeated.status_code == 201
            assert repeated.json()["checkpoint"]["payload"]["checkpoint_id"] == str(
                checkpoint.payload.checkpoint_id
            )
            listed = client.get("/api/v1/integrity/checkpoints")
            assert listed.status_code == 200
            assert [item["payload"]["checkpoint_id"] for item in listed.json()] == [
                str(checkpoint.payload.checkpoint_id)
            ]
            audit = client.get("/api/v1/integrity").json()
            assert audit["checkpoint_checked"] == 1
            assert audit["checkpoint_valid"] == 1
            assert audit["checkpoint_failures"] == []

            with psycopg.connect(database_url) as connection:
                connection.execute(
                    sql.SQL(
                        "ALTER TABLE {}.artifact_ledger DISABLE TRIGGER artifact_ledger_append_only"
                    ).format(sql.Identifier(schema))
                )
                connection.execute(
                    sql.SQL("DELETE FROM {}.artifact_ledger").format(sql.Identifier(schema))
                )
            rollback = client.get("/api/v1/integrity").json()
            assert rollback["ledger_checked"] == 0
            assert rollback["checkpoint_valid"] == 0
            assert rollback["checkpoint_failures"][0]["reason"] == "missing_sequence"
            assert rollback["checkpoint_failures"][0]["expected_sha256"] == (
                checkpoint.payload.ledger_head_sha256
            )

        with (
            pytest.raises(psycopg.Error, match="ledger checkpoints are append-only"),
            psycopg.connect(database_url) as connection,
        ):
            connection.execute(
                sql.SQL("DELETE FROM {}.ledger_checkpoints").format(sql.Identifier(schema))
            )
    finally:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_ed25519_artifacts_support_independent_public_verification(database_url: str) -> None:
    schema = f"test_{uuid4().hex}"
    private_key, public_key = generate_ed25519_keypair()
    _, unrelated_public_key = generate_ed25519_keypair()
    signer = ArtifactKeyring(
        active_key_id="release-attestor",
        active_algorithm=ED25519,
        ed25519_private_keys={"release-attestor": private_key},
    )
    verifier = ArtifactKeyring(ed25519_public_keys={"release-attestor": public_key})
    wrong_verifier = ArtifactKeyring(ed25519_public_keys={"release-attestor": unrelated_public_key})
    try:
        with TestClient(create_app(database_url, schema=schema, artifact_keyring=signer)) as client:
            created = client.post(
                "/api/v1/evaluations",
                json={
                    "suite_path": "examples/suites/coding_repair.yaml",
                    "agent_version": "candidate_fixed",
                },
            )
            assert created.status_code == 201
            run_id = created.json()["run_id"]

        with TestClient(
            create_app(database_url, schema=schema, artifact_keyring=verifier)
        ) as client:
            assert client.get(f"/api/v1/runs/{run_id}").status_code == 200
            report = client.get("/api/v1/integrity").json()
            assert report["valid"] == 1
            assert report["signed"] == 1
            assert report["signature_algorithms"] == {ED25519: 1}

        with psycopg.connect(database_url) as connection:
            envelope = connection.execute(
                sql.SQL(
                    "SELECT signature_algorithm, signature_key_id, signature_value "
                    "FROM {}.evaluation_runs WHERE run_id = %s"
                ).format(sql.Identifier(schema)),
                (run_id,),
            ).fetchone()
        assert envelope is not None
        assert envelope[0:2] == (ED25519, "release-attestor")
        assert len(base64.b64decode(envelope[2], validate=True)) == 64

        with TestClient(
            create_app(database_url, schema=schema, artifact_keyring=wrong_verifier)
        ) as client:
            blocked = client.get(f"/api/v1/runs/{run_id}")
            assert blocked.status_code == 409
            assert "failed ed25519 authenticity verification" in blocked.json()["detail"]
            failure = client.get("/api/v1/integrity").json()["failures"][0]
            assert failure["failure_kind"] == "signature"
            assert failure["signature_algorithm"] == ED25519
    finally:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


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

    undiscoverable = api_client.post(
        "/api/v1/guardrails/config-activations",
        json={"config_id": "missing_policy", "version": "1.0.0"},
    )
    assert undiscoverable.status_code == 409
    assert "is not serving" in undiscoverable.json()["detail"]

    for version, digest in (("2026.07.1", "1" * 64), ("2026.07.2", "2" * 64)):
        registered = api_client.post(
            "/api/v1/guardrails/config-versions",
            json={
                "config_id": "content_safety",
                "version": version,
                "bundle_sha256": digest,
                "description": f"policy {version}",
            },
        )
        assert registered.status_code == 201
        assert registered.json()["active"] is False
        assert registered.json()["created_by"] == "local-trust"

    duplicate = api_client.post(
        "/api/v1/guardrails/config-versions",
        json={
            "config_id": "content_safety",
            "version": "2026.07.1",
            "bundle_sha256": "f" * 64,
        },
    )
    assert duplicate.status_code == 409
    assert "already registered" in duplicate.json()["detail"]

    unregistered = api_client.post(
        "/api/v1/guardrails/config-activations",
        json={"config_id": "content_safety", "version": "2099.01.1"},
    )
    assert unregistered.status_code == 404

    activated_v1 = api_client.post(
        "/api/v1/guardrails/config-activations",
        json={"config_id": "content_safety", "version": "2026.07.1"},
    )
    assert activated_v1.status_code == 201
    assert activated_v1.json()["bundle_sha256"] == "1" * 64
    activation_v1 = activated_v1.json()["activation_id"]

    versions = api_client.get("/api/v1/guardrails/config-versions").json()
    assert {item["version"]: item["active"] for item in versions} == {
        "2026.07.1": True,
        "2026.07.2": False,
    }

    created = api_client.post(
        "/api/v1/guardrails/check",
        json={
            "model": "meta/llama-3.1-8b-instruct",
            "config_id": "content_safety",
            "input_text": "user request",
            "output_text": "candidate response",
            "config_version": "2026.07.1",
        },
    )
    assert created.status_code == 201
    evidence_id = created.json()["evidence_id"]
    assert created.json()["evidence"]["passed_through"] is False
    assert created.json()["evidence"]["activated_rails"][0]["name"] == (
        "content safety check output"
    )
    assert created.json()["evidence"]["config_version"] == "2026.07.1"
    assert created.json()["evidence"]["config_bundle_sha256"] == "1" * 64
    assert created.json()["evidence"]["config_activation_id"] == activation_v1

    activated_v2 = api_client.post(
        "/api/v1/guardrails/config-activations",
        json={"config_id": "content_safety", "version": "2026.07.2"},
    )
    assert activated_v2.status_code == 201
    stale_check = api_client.post(
        "/api/v1/guardrails/check",
        json={
            "model": "meta/llama-3.1-8b-instruct",
            "config_id": "content_safety",
            "config_version": "2026.07.1",
            "input_text": "user request",
        },
    )
    assert stale_check.status_code == 409
    assert "is not active" in stale_check.json()["detail"]

    rollback = api_client.post(
        "/api/v1/guardrails/config-activations",
        json={"config_id": "content_safety", "version": "2026.07.1"},
    )
    assert rollback.status_code == 201
    history = api_client.get(
        "/api/v1/guardrails/config-activations?config_id=content_safety"
    ).json()
    assert [item["version"] for item in history] == ["2026.07.1", "2026.07.2", "2026.07.1"]

    listed = api_client.get("/api/v1/guardrails/evidence")
    assert listed.status_code == 200
    assert listed.json()[0]["evidence_id"] == evidence_id
    assert listed.json()[0]["config_id"] == "content_safety"
    assert listed.json()[0]["config_version"] == "2026.07.1"
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
    assert "content_safety@2026.07.1" in dashboard.text
    detail = api_client.get(f"/guardrails/evidence/{evidence_id}")
    assert detail.status_code == 200
    assert "Guardrail Check" in detail.text
    assert "Intervention" in detail.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in detail.text
    assert "<script>alert(1)</script>" not in detail.text
    assert "I cannot help with that request." in detail.text
    assert "content safety check output" in detail.text
    assert "Bundle SHA-256 " + "1" * 64 in detail.text
    assert f"Activation {activation_v1}" in detail.text

    integrity = api_client.get("/api/v1/integrity")
    integrity_payload = integrity.json()
    assert len(integrity_payload.pop("ledger_head_sha256")) == 64
    assert integrity_payload == {
        "checked": 1,
        "valid": 1,
        "signed": 0,
        "unsigned": 1,
        "signature_algorithms": {},
        "ledger_checked": 1,
        "ledger_valid": 1,
        "ledger_failures": [],
        "checkpoint_checked": 0,
        "checkpoint_valid": 0,
        "checkpoint_failures": [],
        "failures": [],
    }

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
    assert api_client.get("/api/v1/guardrails/efficacy").status_code == 409
    browser_blocked = api_client.get(f"/guardrails/evidence/{evidence_id}")
    assert browser_blocked.status_code == 409
    assert api_client.get(f"/api/v1/guardrails/evidence/{uuid4()}").status_code == 404
    assert api_client.get(f"/guardrails/evidence/{uuid4()}").status_code == 404


def test_guardrail_efficacy_compares_labeled_policy_versions(
    api_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def configs(_client) -> list[GuardrailsConfig]:  # type: ignore[no-untyped-def]
        return [GuardrailsConfig(id="content_safety")]

    async def check(_client, **kwargs) -> GuardrailEvidence:  # type: ignore[no-untyped-def]
        submitted = kwargs["output_text"] or kwargs["input_text"]
        passed_through = submitted.startswith("safe")
        return GuardrailEvidence(
            config_id="content_safety",
            model="nim/model",
            submitted_text=submitted,
            response_text=submitted if passed_through else "blocked",
            passed_through=passed_through,
        )

    client_type = type(api_client.app.state.guardrails_client)
    monkeypatch.setattr(client_type, "configs", configs)
    monkeypatch.setattr(client_type, "check", check)
    registered = api_client.post(
        "/api/v1/guardrails/config-versions",
        json={
            "config_id": "content_safety",
            "version": "1.0",
            "bundle_sha256": "a" * 64,
        },
    )
    assert registered.status_code == 201
    assert (
        api_client.post(
            "/api/v1/guardrails/config-activations",
            json={"config_id": "content_safety", "version": "1.0"},
        ).status_code
        == 201
    )

    cases = [
        ("unsafe-tp", "intervention"),
        ("unsafe-fp", "pass_through"),
        ("safe-tn", "pass_through"),
        ("safe-fn", "intervention"),
        ("safe-unlabeled", None),
    ]
    for output_text, expected_action in cases:
        created = api_client.post(
            "/api/v1/guardrails/check",
            json={
                "model": "nim/model",
                "config_id": "content_safety",
                "input_text": "request",
                "output_text": output_text,
                "expected_action": expected_action,
            },
        )
        assert created.status_code == 201

    response = api_client.get("/api/v1/guardrails/efficacy?config_id=content_safety")
    assert response.status_code == 200
    report = response.json()
    assert report["total_checks"] == 5
    assert report["labeled_checks"] == 4
    metrics = report["versions"][0]
    assert metrics["config_version"] == "1.0"
    assert metrics["label_coverage"] == pytest.approx(0.8)
    assert metrics["intervention_rate"] == pytest.approx(0.4)
    assert metrics["accuracy"] == pytest.approx(0.5)
    assert metrics["precision"] == pytest.approx(0.5)
    assert metrics["recall"] == pytest.approx(0.5)
    assert metrics["false_positive_rate"] == pytest.approx(0.5)

    metrics_payload = api_client.get("/metrics").text
    assert "aecontrol_guardrail_policy_accuracy 0.500000" in metrics_payload
    dashboard = api_client.get("/").text
    assert "Policy Efficacy (30 days)" in dashboard
    assert "content_safety@1.0" in dashboard
    assert "4 (80.0%)" in dashboard
    assert "Policy accuracy<b>50.0%" in dashboard

    invalid_window = api_client.get(
        "/api/v1/guardrails/efficacy?since=2026-08-01T00:00:00Z&until=2026-07-01T00:00:00Z"
    )
    assert invalid_window.status_code == 422


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
    assert completed.started_at is not None
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
    assert first_attempt.started_at is None
    assert first_attempt.error is not None

    second_attempt = asyncio.run(EvaluationWorker(store, "retry-worker").run_once())
    assert second_attempt is not None
    assert second_attempt.status == JobStatus.FAILED
    assert second_attempt.attempts == 2
    assert second_attempt.started_at is not None


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
    assert claimed.started_at is not None
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


def test_mig_profile_admission_is_persisted_diagnosed_and_leased(api_client: TestClient) -> None:
    store: ArtifactStore = api_client.app.state.store
    constrained = store.enqueue_job(
        "examples/suites/coding_repair.yaml",
        "nim/meta/llama-test",
        required_accelerator=Accelerator.CUDA,
        required_mig_profile="3g.40gb",
        minimum_gpu_memory_available_mb=32000,
    )
    assert store.get_job(constrained.job_id).required_mig_profile == "3g.40gb"

    base = WorkerCapabilities(
        hostname="mig-host",
        operating_system="linux",
        architecture="x86_64",
        cpu_count=8,
        accelerators=[Accelerator.CPU, Accelerator.CUDA],
        labels={"runtime": "nvidia-nim"},
    )
    wrong_profile = base.model_copy(
        update={
            "gpus": [
                GpuDevice(
                    name="H100 MIG",
                    memory_total_mb=40960,
                    memory_used_mb=1000,
                    compute_capability="9.0",
                    mig_profile="2g.20gb",
                )
            ]
        }
    )
    store.register_worker("wrong-mig", wrong_profile)
    assert store.lease_job("wrong-mig", capabilities=wrong_profile) is None
    diagnostic = api_client.get(f"/api/v1/jobs/{constrained.job_id}/placement").json()
    assert diagnostic["workers"][0]["reasons"] == [
        "MIG profile requires '3g.40gb', available: 2g.20gb"
    ]

    matching_profile = base.model_copy(
        update={
            "gpus": [
                GpuDevice(
                    name="H100 MIG",
                    memory_total_mb=40960,
                    memory_used_mb=4096,
                    compute_capability="9.0",
                    mig_profile="3g.40gb",
                )
            ]
        }
    )
    store.register_worker("matching-mig", matching_profile)
    forecast = api_client.get("/api/v1/capacity/gpu").json()
    assert forecast["first_wave_jobs"] == 1
    assert forecast["jobs"][0]["assigned_worker_id"] == "matching-mig"

    claimed = store.lease_job("matching-mig", capabilities=matching_profile)
    assert claimed is not None
    assert claimed.job_id == constrained.job_id
    assert claimed.required_mig_profile == "3g.40gb"

    normalized = api_client.post(
        "/api/v1/jobs",
        json={
            "suite_path": "examples/suites/coding_repair.yaml",
            "agent_version": "baseline",
            "required_accelerator": "cuda",
            "required_mig_profile": " 1G.10GB ",
        },
    )
    assert normalized.status_code == 202
    assert normalized.json()["required_mig_profile"] == "1g.10gb"

    invalid = api_client.post(
        "/api/v1/jobs",
        json={
            "suite_path": "examples/suites/coding_repair.yaml",
            "agent_version": "baseline",
            "required_accelerator": "cuda",
            "required_mig_profile": "mig-3g-40gb",
        },
    )
    assert invalid.status_code == 422


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


def test_gpu_capacity_forecast_spans_api_dashboard_and_metrics(api_client: TestClient) -> None:
    store: ArtifactStore = api_client.app.state.store
    for worker_id, memory_mb, used_mb, utilization in (
        ("a100-worker", 81920, 20000, 30),
        ("l4-worker", 24576, 4096, 10),
    ):
        store.register_worker(
            worker_id,
            WorkerCapabilities(
                hostname=worker_id,
                operating_system="linux",
                architecture="x86_64",
                cpu_count=16,
                accelerators=[Accelerator.CPU, Accelerator.CUDA],
                labels={"runtime": "nvidia-nim"},
                gpus=[
                    GpuDevice(
                        uuid=f"GPU-{worker_id}",
                        name=worker_id,
                        memory_total_mb=memory_mb,
                        memory_used_mb=used_mb,
                        utilization_percent=utilization,
                        compute_capability="9.0",
                    )
                ],
            ),
        )

    historical_jobs = [
        store.enqueue_job(
            "examples/suites/coding_repair.yaml",
            f"nim/history-{duration}",
            required_accelerator=Accelerator.CUDA,
        )
        for duration in range(10, 101, 10)
    ]
    with psycopg.connect(store.database_url) as connection:
        for job, duration in zip(historical_jobs, range(10, 101, 10), strict=True):
            connection.execute(
                sql.SQL(
                    """UPDATE {}.evaluation_jobs
                       SET status = 'completed',
                           started_at = now() - (%s * interval '1 second'),
                           updated_at = now()
                       WHERE job_id = %s"""
                ).format(sql.Identifier(store.schema)),
                (duration, job.job_id),
            )

    for priority, memory_mb in ((10, 16000), (5, 40000), (0, 16000), (-1, 100000)):
        response = api_client.post(
            "/api/v1/jobs",
            json={
                "suite_path": "examples/suites/coding_repair.yaml",
                "agent_version": f"nim/capacity-{priority}",
                "priority": priority,
                "required_accelerator": "cuda",
                "minimum_gpu_memory_mb": memory_mb,
            },
        )
        assert response.status_code == 202

    response = api_client.get("/api/v1/capacity/gpu")
    assert response.status_code == 200
    forecast = response.json()
    assert forecast["active_cuda_workers"] == 2
    assert forecast["active_gpus"] == 2
    assert forecast["available_gpu_memory_mb"] == 82400
    assert forecast["queued_cuda_jobs"] == 4
    assert forecast["first_wave_jobs"] == 2
    assert forecast["deferred_jobs"] == 1
    assert forecast["blocked_jobs"] == 1
    assert forecast["minimum_clearance_waves"] == 2
    assert forecast["estimated_clearance_seconds"] == pytest.approx(182)
    assert forecast["estimate_confidence"] == "high"
    assert forecast["duration_estimates"] == [
        {
            "mig_profile": None,
            "sample_count": 10,
            "average_seconds": pytest.approx(55),
            "p90_seconds": pytest.approx(91),
        }
    ]
    assert [job["priority"] for job in forecast["jobs"]] == [10, 5, 0, -1]

    dashboard = api_client.get("/")
    assert dashboard.status_code == 200
    assert "GPU Capacity Forecast" in dashboard.text
    assert "GPU first wave<b>2/4" in dashboard.text
    assert "GPU clearance<b>2 waves" in dashboard.text
    assert "GPU queue ETA<b>182s (high)" in dashboard.text
    assert "capacity-10" in dashboard.text

    metrics = api_client.get("/metrics")
    assert metrics.status_code == 200
    assert 'aecontrol_gpu_queue_jobs{state="first_wave"} 2' in metrics.text
    assert 'aecontrol_gpu_queue_jobs{state="deferred"} 1' in metrics.text
    assert 'aecontrol_gpu_queue_jobs{state="blocked"} 1' in metrics.text
    assert "aecontrol_gpu_queue_clearance_waves 2" in metrics.text
    assert "aecontrol_gpu_queue_estimated_clearance_seconds 182.000000" in metrics.text
    assert 'aecontrol_gpu_queue_estimate_confidence{level="high"} 1' in metrics.text
    assert 'aecontrol_gpu_job_duration_samples{mig_profile="all"} 10' in metrics.text

    profile_history = store.enqueue_job(
        "examples/suites/coding_repair.yaml",
        "nim/profile-history",
        required_accelerator=Accelerator.CUDA,
        required_mig_profile="3g.40gb",
    )
    with psycopg.connect(store.database_url) as connection:
        connection.execute(
            sql.SQL(
                """UPDATE {}.evaluation_jobs
                   SET status = 'completed', started_at = now() - interval '120 seconds',
                       updated_at = now()
                   WHERE job_id = %s"""
            ).format(sql.Identifier(store.schema)),
            (profile_history.job_id,),
        )
    refreshed = api_client.get("/api/v1/capacity/gpu").json()
    profile_estimate = next(
        item for item in refreshed["duration_estimates"] if item["mig_profile"] == "3g.40gb"
    )
    assert profile_estimate == {
        "mig_profile": "3g.40gb",
        "sample_count": 1,
        "average_seconds": pytest.approx(120),
        "p90_seconds": pytest.approx(120),
    }


def test_gpu_demand_forecast_spans_postgres_api_dashboard_and_metrics(
    api_client: TestClient,
) -> None:
    store: ArtifactStore = api_client.app.state.store
    observed = datetime.now(UTC)
    store.register_worker(
        "demand-gpu-worker",
        WorkerCapabilities(
            hostname="demand-gpu-worker",
            operating_system="linux",
            architecture="x86_64",
            cpu_count=16,
            accelerators=[Accelerator.CPU, Accelerator.CUDA],
            gpus=[
                GpuDevice(
                    uuid="GPU-demand",
                    name="NVIDIA H100",
                    memory_total_mb=81920,
                    compute_capability="9.0",
                )
            ],
        ),
    )
    historical_jobs = [
        store.enqueue_job(
            "examples/suites/coding_repair.yaml",
            f"nim/demand-history-{index}",
            required_accelerator=Accelerator.CUDA,
        )
        for index in range(20)
    ]
    target_hour = observed.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    with psycopg.connect(store.database_url) as connection:
        for index, job in enumerate(historical_jobs):
            created_at = target_hour - timedelta(weeks=index // 4 + 1)
            connection.execute(
                sql.SQL(
                    """UPDATE {}.evaluation_jobs
                       SET status = 'completed', created_at = %s,
                           started_at = now() - interval '60 seconds', updated_at = now()
                       WHERE job_id = %s"""
                ).format(sql.Identifier(store.schema)),
                (created_at, job.job_id),
            )

    queued = api_client.post(
        "/api/v1/jobs",
        json={
            "suite_path": "examples/suites/coding_repair.yaml",
            "agent_version": "nim/demand-queued",
            "required_accelerator": "cuda",
        },
    )
    assert queued.status_code == 202

    response = api_client.get("/api/v1/capacity/gpu/demand")
    assert response.status_code == 200
    forecast = response.json()
    assert forecast["historical_cuda_jobs"] == 20
    assert forecast["current_queued_cuda_jobs"] == 1
    assert forecast["current_running_cuda_jobs"] == 0
    assert forecast["predicted_cuda_arrivals"] == pytest.approx(4)
    assert forecast["average_cuda_duration_seconds"] == pytest.approx(60)
    assert forecast["projected_gpu_seconds"] == pytest.approx(300)
    assert forecast["available_gpu_seconds"] == 86400
    assert forecast["projected_capacity_ratio"] == pytest.approx(300 / 86400)
    assert forecast["confidence"] == "high"
    assert forecast["saturation"] == "within_capacity"
    busiest = max(forecast["hours"], key=lambda item: item["predicted_arrivals"])
    assert busiest["historical_occurrences"] == 5
    assert busiest["historical_arrivals"] == 20
    assert busiest["predicted_arrivals"] == pytest.approx(4)

    dashboard = api_client.get("/")
    assert "GPU Demand Forecast" in dashboard.text
    assert "24h GPU arrivals<b>4.00" in dashboard.text
    assert "Demand confidence<b>high" in dashboard.text

    metrics = api_client.get("/metrics")
    assert "aecontrol_gpu_demand_predicted_arrivals 4.000000" in metrics.text
    assert "aecontrol_gpu_demand_capacity_ratio 0.003472" in metrics.text
    assert 'aecontrol_gpu_demand_confidence{level="high"} 1' in metrics.text
