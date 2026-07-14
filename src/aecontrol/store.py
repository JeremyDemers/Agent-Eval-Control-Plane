from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Literal, cast
from uuid import UUID

import psycopg
from psycopg import sql
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from aecontrol.capacity import forecast_gpu_capacity
from aecontrol.database import DatabasePoolSnapshot, DatabaseRuntimeConfiguration
from aecontrol.demand import DEFAULT_LOOKBACK_DAYS, forecast_gpu_demand
from aecontrol.guardrails import (
    GuardrailConfigActivation,
    GuardrailConfigVersion,
    GuardrailEfficacyReport,
    GuardrailEvidence,
    StoredGuardrailEvidence,
    StoredGuardrailEvidenceSummary,
    build_guardrail_efficacy_report,
)
from aecontrol.integrity import (
    HMAC_SHA256,
    LEDGER_GENESIS_SHA256,
    ArtifactAuthenticityError,
    ArtifactIntegrityError,
    ArtifactKeyring,
    artifact_digest,
    ledger_entry_digest,
)
from aecontrol.models import (
    Accelerator,
    ArtifactIntegrityItem,
    ArtifactIntegrityReport,
    ArtifactLedgerFailure,
    EvaluationJob,
    EvaluationRun,
    GpuCapacityForecast,
    GpuDemandForecast,
    GpuDurationEstimate,
    JobPlacementDiagnostic,
    JobStatus,
    OperationalSnapshot,
    QualityGateDecision,
    RunComparison,
    StoredComparison,
    StoredComparisonSummary,
    StoredRunSummary,
    WorkerCapabilities,
    WorkerRecord,
)
from aecontrol.placement import DEFAULT_WORKER_ACTIVE_SECONDS, diagnose_placement
from aecontrol.tenancy import current_tenant_id
from aecontrol.tenants import (
    LastTenantAdminError,
    ResolvedTenantAPIKey,
    TenantAPIKeyRecord,
    TenantConflictError,
    TenantRecord,
    TenantScope,
    TenantStatus,
    TenantSuspendedError,
)

SCHEMA_VERSION = 15
SIGNED_ARTIFACT_TABLES = ("evaluation_runs", "comparisons", "guardrail_evidence")
TENANT_TABLES = (
    "evaluation_runs",
    "comparisons",
    "guardrail_evidence",
    "guardrail_config_versions",
    "guardrail_config_activations",
    "evaluation_jobs",
    "workers",
    "artifact_ledger",
)


class ArtifactStore:
    """PostgreSQL storage for complete evaluation and comparison artifacts."""

    def __init__(
        self,
        database_url: str,
        schema: str = "public",
        keyring: ArtifactKeyring | None = None,
        database_config: DatabaseRuntimeConfiguration | None = None,
    ) -> None:
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", schema):
            msg = f"invalid PostgreSQL schema name: {schema}"
            raise ValueError(msg)
        self.database_url = database_url
        self.schema = schema
        self.keyring = keyring if keyring is not None else ArtifactKeyring.from_environment()
        self.database_config = database_config or DatabaseRuntimeConfiguration()
        self._initialized = False
        self._closed = False
        self._initialize_lock = Lock()
        self._pool: ConnectionPool[psycopg.Connection[dict[str, object]]] | None = None
        if self.database_config.pooling_enabled:
            self._pool = ConnectionPool(
                self.database_url,
                kwargs={"row_factory": dict_row},
                min_size=self.database_config.pool_min_size,
                max_size=self.database_config.pool_max_size,
                timeout=self.database_config.pool_timeout_seconds,
                max_waiting=self.database_config.pool_max_waiting,
                check=ConnectionPool.check_connection,
                configure=self._configure_pool_connection,
                name="aecontrol-store",
                open=False,
            )

    def initialize(self) -> None:
        if self._closed:
            raise RuntimeError("artifact store is closed")
        if self._initialized:
            return
        with self._initialize_lock:
            if self._initialized:
                return
            try:
                if self._pool is not None:
                    self._pool.open()
                    self._pool.wait(timeout=self.database_config.pool_timeout_seconds)
                self._initialize_schema()
                self._initialized = True
            except BaseException:
                if self._pool is not None:
                    self._pool.close()
                    self._closed = True
                raise

    def close(self) -> None:
        with self._initialize_lock:
            if self._closed:
                return
            self._closed = True
            if self._pool is not None:
                self._pool.close()

    @property
    def connection_mode(self) -> str:
        return "pooled" if self._pool is not None else "direct"

    @property
    def closed(self) -> bool:
        return self._closed

    def database_pool_snapshot(self) -> DatabasePoolSnapshot | None:
        if self._pool is None:
            return None
        stats = self._pool.get_stats()
        return DatabasePoolSnapshot(
            minimum=int(stats.get("pool_min", self.database_config.pool_min_size)),
            maximum=int(stats.get("pool_max", self.database_config.pool_max_size)),
            size=int(stats.get("pool_size", 0)),
            available=int(stats.get("pool_available", 0)),
            waiting=int(stats.get("requests_waiting", 0)),
        )

    def _initialize_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "SELECT set_config('lock_timeout', %s, true)",
                (f"{self.database_config.migration_lock_timeout_seconds}s",),
            )
            connection.execute(
                "SELECT pg_advisory_xact_lock(%s)",
                (self._migration_lock_key(),),
            )
            connection.execute(
                sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(self.schema))
            )
            self._set_search_path(connection)
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_metadata (version INTEGER NOT NULL)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS evaluation_runs (
                    run_id UUID PRIMARY KEY,
                    suite_name TEXT NOT NULL,
                    dataset_name TEXT NOT NULL,
                    dataset_version TEXT NOT NULL,
                    agent_version TEXT NOT NULL,
                    started_at TIMESTAMPTZ NOT NULL,
                    completed_at TIMESTAMPTZ NOT NULL,
                    case_count INTEGER NOT NULL CHECK (case_count >= 0),
                    hidden_pass_rate DOUBLE PRECISION NOT NULL
                        CHECK (hidden_pass_rate BETWEEN 0 AND 1),
                    payload JSONB NOT NULL
                )
                """
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_runs_completed_at
                   ON evaluation_runs(completed_at DESC)"""
            )
            connection.execute(
                "ALTER TABLE evaluation_runs ADD COLUMN IF NOT EXISTS payload_sha256 TEXT"
            )
            connection.execute(
                "ALTER TABLE evaluation_runs ADD COLUMN IF NOT EXISTS signature_hmac_sha256 TEXT"
            )
            connection.execute(
                "ALTER TABLE evaluation_runs ADD COLUMN IF NOT EXISTS signature_key_id TEXT"
            )
            connection.execute(
                "ALTER TABLE evaluation_runs ADD COLUMN IF NOT EXISTS signature_algorithm TEXT"
            )
            connection.execute(
                "ALTER TABLE evaluation_runs ADD COLUMN IF NOT EXISTS signature_value TEXT"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS comparisons (
                    comparison_id UUID PRIMARY KEY,
                    baseline_run_id UUID NOT NULL REFERENCES evaluation_runs(run_id),
                    candidate_run_id UUID NOT NULL REFERENCES evaluation_runs(run_id),
                    created_at TIMESTAMPTZ NOT NULL,
                    outcome TEXT NOT NULL,
                    paired_cases INTEGER NOT NULL CHECK (paired_cases >= 0),
                    aggregate_pass_rate_delta DOUBLE PRECISION NOT NULL,
                    payload JSONB NOT NULL
                )
                """
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_comparisons_created_at
                   ON comparisons(created_at DESC)"""
            )
            connection.execute(
                "ALTER TABLE comparisons ADD COLUMN IF NOT EXISTS payload_sha256 TEXT"
            )
            connection.execute(
                "ALTER TABLE comparisons ADD COLUMN IF NOT EXISTS signature_hmac_sha256 TEXT"
            )
            connection.execute(
                "ALTER TABLE comparisons ADD COLUMN IF NOT EXISTS signature_key_id TEXT"
            )
            connection.execute(
                "ALTER TABLE comparisons ADD COLUMN IF NOT EXISTS signature_algorithm TEXT"
            )
            connection.execute(
                "ALTER TABLE comparisons ADD COLUMN IF NOT EXISTS signature_value TEXT"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS guardrail_evidence (
                    evidence_id UUID PRIMARY KEY,
                    created_at TIMESTAMPTZ NOT NULL,
                    config_id TEXT NOT NULL,
                    model TEXT NOT NULL,
                    passed_through BOOLEAN NOT NULL,
                    payload JSONB NOT NULL,
                    payload_sha256 TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_guardrail_evidence_created_at
                   ON guardrail_evidence(created_at DESC)"""
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_guardrail_evidence_config
                   ON guardrail_evidence(config_id, created_at DESC)"""
            )
            connection.execute(
                """ALTER TABLE guardrail_evidence ADD COLUMN IF NOT EXISTS
                   signature_hmac_sha256 TEXT"""
            )
            connection.execute(
                "ALTER TABLE guardrail_evidence ADD COLUMN IF NOT EXISTS signature_key_id TEXT"
            )
            connection.execute(
                "ALTER TABLE guardrail_evidence ADD COLUMN IF NOT EXISTS signature_algorithm TEXT"
            )
            connection.execute(
                "ALTER TABLE guardrail_evidence ADD COLUMN IF NOT EXISTS signature_value TEXT"
            )
            connection.execute(
                "ALTER TABLE guardrail_evidence ADD COLUMN IF NOT EXISTS config_version TEXT"
            )
            connection.execute(
                "ALTER TABLE guardrail_evidence ADD COLUMN IF NOT EXISTS expected_action TEXT"
            )
            connection.execute(
                """
                DO $$ BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'guardrail_evidence_expected_action_check'
                          AND conrelid = 'guardrail_evidence'::regclass
                    ) THEN
                        ALTER TABLE guardrail_evidence
                        ADD CONSTRAINT guardrail_evidence_expected_action_check
                        CHECK (expected_action IN ('pass_through', 'intervention'));
                    END IF;
                END $$
                """
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_guardrail_evidence_efficacy
                   ON guardrail_evidence(config_id, config_version, created_at DESC)"""
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS artifact_ledger (
                    tenant_id TEXT,
                    sequence BIGINT NOT NULL CHECK (sequence >= 1),
                    artifact_type TEXT NOT NULL CHECK (
                        artifact_type IN ('run', 'comparison', 'guardrail_evidence')
                    ),
                    artifact_id UUID NOT NULL,
                    payload_sha256 TEXT NOT NULL CHECK (payload_sha256 ~ '^[a-f0-9]{64}$'),
                    signature_algorithm TEXT,
                    signing_key_id TEXT,
                    signature_value TEXT,
                    previous_entry_sha256 TEXT NOT NULL CHECK (
                        previous_entry_sha256 ~ '^[a-f0-9]{64}$'
                    ),
                    entry_sha256 TEXT NOT NULL CHECK (entry_sha256 ~ '^[a-f0-9]{64}$'),
                    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    PRIMARY KEY (tenant_id, sequence),
                    UNIQUE (tenant_id, artifact_type, artifact_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS control_plane_tenants (
                    tenant_id TEXT PRIMARY KEY CHECK (
                        tenant_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'
                    ),
                    display_name TEXT NOT NULL CHECK (
                        char_length(display_name) BETWEEN 1 AND 200
                    ),
                    status TEXT NOT NULL CHECK (status IN ('active', 'suspended')),
                    created_at TIMESTAMPTZ NOT NULL,
                    created_by TEXT NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL,
                    updated_by TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS tenant_api_keys (
                    tenant_id TEXT NOT NULL REFERENCES control_plane_tenants(tenant_id),
                    key_id TEXT NOT NULL CHECK (
                        key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
                    ),
                    secret_sha256 TEXT NOT NULL UNIQUE CHECK (
                        secret_sha256 ~ '^[a-f0-9]{64}$'
                    ),
                    scopes TEXT[] NOT NULL CHECK (
                        cardinality(scopes) > 0
                        AND scopes <@ ARRAY['read', 'write', 'admin']::TEXT[]
                    ),
                    created_at TIMESTAMPTZ NOT NULL,
                    created_by TEXT NOT NULL,
                    revoked_at TIMESTAMPTZ,
                    revoked_by TEXT,
                    PRIMARY KEY (tenant_id, key_id),
                    CHECK (
                        (revoked_at IS NULL AND revoked_by IS NULL)
                        OR (revoked_at IS NOT NULL AND revoked_by IS NOT NULL)
                    )
                )
                """
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_tenant_api_keys_active_digest
                   ON tenant_api_keys(secret_sha256) WHERE revoked_at IS NULL"""
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS guardrail_config_versions (
                    config_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    bundle_sha256 TEXT NOT NULL,
                    description TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    created_by TEXT NOT NULL,
                    PRIMARY KEY (config_id, version)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS guardrail_config_activations (
                    activation_sequence BIGSERIAL PRIMARY KEY,
                    activation_id UUID NOT NULL UNIQUE,
                    config_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    activated_at TIMESTAMPTZ NOT NULL,
                    activated_by TEXT NOT NULL,
                    FOREIGN KEY (config_id, version)
                        REFERENCES guardrail_config_versions(config_id, version)
                )
                """
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_guardrail_config_activations_latest
                   ON guardrail_config_activations(config_id, activation_sequence DESC)"""
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS evaluation_jobs (
                    job_id UUID PRIMARY KEY,
                    suite_path TEXT NOT NULL,
                    agent_version TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('queued', 'running', 'completed', 'failed', 'cancelled')
                    ),
                    priority INTEGER NOT NULL CHECK (priority BETWEEN -100 AND 100),
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                    max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 10),
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL,
                    lease_owner TEXT,
                    lease_expires_at TIMESTAMPTZ,
                    run_id UUID REFERENCES evaluation_runs(run_id),
                    error TEXT
                )
                """
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_jobs_claim
                   ON evaluation_jobs(priority DESC, created_at)
                   WHERE status IN ('queued', 'running')"""
            )
            connection.execute(
                """ALTER TABLE evaluation_jobs ADD COLUMN IF NOT EXISTS
                   required_accelerator TEXT NOT NULL DEFAULT 'cpu'"""
            )
            connection.execute(
                """ALTER TABLE evaluation_jobs ADD COLUMN IF NOT EXISTS
                   required_labels JSONB NOT NULL DEFAULT '{}'::jsonb"""
            )
            connection.execute(
                """ALTER TABLE evaluation_jobs ADD COLUMN IF NOT EXISTS
                   minimum_gpu_memory_mb INTEGER NOT NULL DEFAULT 0"""
            )
            connection.execute(
                """ALTER TABLE evaluation_jobs ADD COLUMN IF NOT EXISTS
                   minimum_cuda_compute_capability DOUBLE PRECISION"""
            )
            connection.execute(
                """ALTER TABLE evaluation_jobs ADD COLUMN IF NOT EXISTS
                   minimum_gpu_memory_available_mb INTEGER NOT NULL DEFAULT 0"""
            )
            connection.execute(
                """ALTER TABLE evaluation_jobs ADD COLUMN IF NOT EXISTS
                   maximum_gpu_utilization_percent DOUBLE PRECISION"""
            )
            connection.execute(
                "ALTER TABLE evaluation_jobs ADD COLUMN IF NOT EXISTS traceparent TEXT"
            )
            connection.execute(
                "ALTER TABLE evaluation_jobs ADD COLUMN IF NOT EXISTS request_id TEXT"
            )
            connection.execute(
                "ALTER TABLE evaluation_jobs ADD COLUMN IF NOT EXISTS required_mig_profile TEXT"
            )
            connection.execute(
                "ALTER TABLE evaluation_jobs ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ"
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_jobs_gpu_duration
                   ON evaluation_jobs(updated_at DESC)
                   WHERE status = 'completed'
                     AND required_accelerator = 'cuda'
                     AND started_at IS NOT NULL"""
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS workers (
                    worker_id TEXT PRIMARY KEY,
                    capabilities JSONB NOT NULL,
                    registered_at TIMESTAMPTZ NOT NULL,
                    last_seen_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            self._suspend_tenant_isolation(connection)
            self._backfill_artifact_digests(connection)
            self._migrate_signature_envelopes(connection)
            self._enable_tenant_isolation(connection)
            self._suspend_tenant_isolation(connection)
            self._backfill_artifact_ledger(connection)
            self._enable_tenant_isolation(connection)
            self._install_ledger_immutability_trigger(connection)
            connection.execute(
                "ALTER TABLE evaluation_runs ALTER COLUMN payload_sha256 SET NOT NULL"
            )
            connection.execute("ALTER TABLE comparisons ALTER COLUMN payload_sha256 SET NOT NULL")
            row = connection.execute("SELECT version FROM schema_metadata LIMIT 1").fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO schema_metadata(version) VALUES (%s)", (SCHEMA_VERSION,)
                )
                return
            stored_version = cast(int, row["version"])
            if stored_version in {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}:
                connection.execute("UPDATE schema_metadata SET version = %s", (SCHEMA_VERSION,))
            elif stored_version != SCHEMA_VERSION:
                msg = f"unsupported database schema version: {stored_version}"
                raise RuntimeError(msg)

    def create_tenant(
        self,
        tenant_id: str,
        display_name: str,
        key_id: str,
        secret_sha256: str,
        *,
        created_by: str,
    ) -> tuple[TenantRecord, TenantAPIKeyRecord]:
        self.initialize()
        now = datetime.now(UTC)
        try:
            with self._connect() as connection:
                tenant_row = connection.execute(
                    """
                    INSERT INTO control_plane_tenants (
                        tenant_id, display_name, status, created_at, created_by,
                        updated_at, updated_by
                    ) VALUES (%s, %s, 'active', %s, %s, %s, %s)
                    RETURNING tenant_id, display_name, status, created_at, created_by,
                              updated_at, updated_by
                    """,
                    (tenant_id, display_name, now, created_by, now, created_by),
                ).fetchone()
                key_row = connection.execute(
                    """
                    INSERT INTO tenant_api_keys (
                        tenant_id, key_id, secret_sha256, scopes, created_at, created_by
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING tenant_id, key_id, scopes, created_at, created_by,
                              revoked_at, revoked_by
                    """,
                    (tenant_id, key_id, secret_sha256, ["admin"], now, created_by),
                ).fetchone()
        except UniqueViolation as error:
            raise TenantConflictError(f"tenant or API key already exists: {tenant_id}") from error
        if tenant_row is None or key_row is None:
            raise RuntimeError("PostgreSQL did not return the created tenant")
        return TenantRecord.model_validate(tenant_row), TenantAPIKeyRecord.model_validate(key_row)

    def list_tenants(self) -> list[TenantRecord]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT tenant_id, display_name, status, created_at, created_by,
                       updated_at, updated_by
                FROM control_plane_tenants ORDER BY tenant_id
                """
            ).fetchall()
        return [TenantRecord.model_validate(row) for row in rows]

    def get_tenant(self, tenant_id: str) -> TenantRecord:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT tenant_id, display_name, status, created_at, created_by,
                       updated_at, updated_by
                FROM control_plane_tenants WHERE tenant_id = %s
                """,
                (tenant_id,),
            ).fetchone()
        if row is None:
            raise KeyError(tenant_id)
        return TenantRecord.model_validate(row)

    def set_tenant_status(
        self, tenant_id: str, status: TenantStatus, *, updated_by: str
    ) -> TenantRecord:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                UPDATE control_plane_tenants
                SET status = %s, updated_at = %s, updated_by = %s
                WHERE tenant_id = %s
                RETURNING tenant_id, display_name, status, created_at, created_by,
                          updated_at, updated_by
                """,
                (status, datetime.now(UTC), updated_by, tenant_id),
            ).fetchone()
        if row is None:
            raise KeyError(tenant_id)
        return TenantRecord.model_validate(row)

    def tenant_access_allowed(self, tenant_id: str) -> bool:
        """Treat unregistered static-key tenants as active for backward compatibility."""
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT status FROM control_plane_tenants WHERE tenant_id = %s", (tenant_id,)
            ).fetchone()
        return row is None or row["status"] == "active"

    def resolve_tenant_api_key(self, secret_sha256: str) -> ResolvedTenantAPIKey | None:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT key.tenant_id, key.key_id, key.scopes
                FROM tenant_api_keys AS key
                JOIN control_plane_tenants AS tenant USING (tenant_id)
                WHERE key.secret_sha256 = %s
                  AND key.revoked_at IS NULL
                  AND tenant.status = 'active'
                """,
                (secret_sha256,),
            ).fetchone()
        return ResolvedTenantAPIKey.model_validate(row) if row is not None else None

    def issue_tenant_api_key(
        self,
        tenant_id: str,
        key_id: str,
        secret_sha256: str,
        scopes: set[TenantScope],
        *,
        created_by: str,
    ) -> TenantAPIKeyRecord:
        self.initialize()
        try:
            with self._connect() as connection:
                tenant = connection.execute(
                    "SELECT status FROM control_plane_tenants WHERE tenant_id = %s FOR UPDATE",
                    (tenant_id,),
                ).fetchone()
                if tenant is None:
                    raise KeyError(tenant_id)
                if tenant["status"] != "active":
                    raise TenantSuspendedError(f"tenant is suspended: {tenant_id}")
                row = connection.execute(
                    """
                    INSERT INTO tenant_api_keys (
                        tenant_id, key_id, secret_sha256, scopes, created_at, created_by
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING tenant_id, key_id, scopes, created_at, created_by,
                              revoked_at, revoked_by
                    """,
                    (
                        tenant_id,
                        key_id,
                        secret_sha256,
                        sorted(scopes),
                        datetime.now(UTC),
                        created_by,
                    ),
                ).fetchone()
        except UniqueViolation as error:
            raise TenantConflictError(f"API key already exists: {key_id}") from error
        if row is None:
            raise RuntimeError("PostgreSQL did not return the created API key")
        return TenantAPIKeyRecord.model_validate(row)

    def list_tenant_api_keys(self, tenant_id: str) -> list[TenantAPIKeyRecord]:
        self.initialize()
        with self._connect() as connection:
            exists = connection.execute(
                "SELECT 1 FROM control_plane_tenants WHERE tenant_id = %s", (tenant_id,)
            ).fetchone()
            if exists is None:
                raise KeyError(tenant_id)
            rows = connection.execute(
                """
                SELECT tenant_id, key_id, scopes, created_at, created_by,
                       revoked_at, revoked_by
                FROM tenant_api_keys WHERE tenant_id = %s ORDER BY created_at, key_id
                """,
                (tenant_id,),
            ).fetchall()
        return [TenantAPIKeyRecord.model_validate(row) for row in rows]

    def revoke_tenant_api_key(
        self, tenant_id: str, key_id: str, *, revoked_by: str
    ) -> TenantAPIKeyRecord:
        self.initialize()
        with self._connect() as connection:
            tenant = connection.execute(
                "SELECT status FROM control_plane_tenants WHERE tenant_id = %s FOR UPDATE",
                (tenant_id,),
            ).fetchone()
            if tenant is None:
                raise KeyError(tenant_id)
            row = connection.execute(
                """
                SELECT tenant_id, key_id, scopes, created_at, created_by,
                       revoked_at, revoked_by
                FROM tenant_api_keys WHERE tenant_id = %s AND key_id = %s FOR UPDATE
                """,
                (tenant_id, key_id),
            ).fetchone()
            if row is None:
                raise KeyError(key_id)
            if row["revoked_at"] is not None:
                return TenantAPIKeyRecord.model_validate(row)
            if "admin" in cast(list[str], row["scopes"]):
                administrators = connection.execute(
                    """
                    SELECT count(*) AS value FROM tenant_api_keys
                    WHERE tenant_id = %s AND revoked_at IS NULL AND 'admin' = ANY(scopes)
                    """,
                    (tenant_id,),
                ).fetchone()
                if administrators is None or int(str(administrators["value"])) <= 1:
                    raise LastTenantAdminError("cannot revoke the tenant's last active admin key")
            updated = connection.execute(
                """
                UPDATE tenant_api_keys SET revoked_at = %s, revoked_by = %s
                WHERE tenant_id = %s AND key_id = %s
                RETURNING tenant_id, key_id, scopes, created_at, created_by,
                          revoked_at, revoked_by
                """,
                (datetime.now(UTC), revoked_by, tenant_id, key_id),
            ).fetchone()
        if updated is None:
            raise RuntimeError("PostgreSQL did not return the revoked API key")
        return TenantAPIKeyRecord.model_validate(updated)

    def save_run(self, run: EvaluationRun) -> None:
        self.initialize()
        case_count = len(run.case_results)
        hidden_passes = sum(result.hidden_success for result in run.case_results)
        hidden_pass_rate = hidden_passes / case_count if case_count else 0.0
        payload = run.model_dump(mode="json")
        digest = artifact_digest(payload)
        signature_algorithm, signature_key_id, signature = self._sign_artifact(
            "run", run.run_id, digest
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO evaluation_runs (
                    run_id, suite_name, dataset_name, dataset_version, agent_version,
                    started_at, completed_at, case_count, hidden_pass_rate, payload, payload_sha256,
                    signature_algorithm, signature_key_id, signature_value
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(run_id) DO UPDATE SET
                    suite_name = excluded.suite_name,
                    dataset_name = excluded.dataset_name,
                    dataset_version = excluded.dataset_version,
                    agent_version = excluded.agent_version,
                    started_at = excluded.started_at,
                    completed_at = excluded.completed_at,
                    case_count = excluded.case_count,
                    hidden_pass_rate = excluded.hidden_pass_rate,
                    payload = excluded.payload,
                    payload_sha256 = excluded.payload_sha256,
                    signature_algorithm = excluded.signature_algorithm,
                    signature_key_id = excluded.signature_key_id,
                    signature_value = excluded.signature_value,
                    signature_hmac_sha256 = NULL
                """,
                (
                    run.run_id,
                    run.suite_name,
                    run.dataset_name,
                    run.dataset_version,
                    run.agent_version,
                    run.started_at,
                    run.completed_at,
                    case_count,
                    hidden_pass_rate,
                    Jsonb(payload),
                    digest,
                    signature_algorithm,
                    signature_key_id,
                    signature,
                ),
            )
            self._append_artifact_ledger(
                connection,
                "run",
                run.run_id,
                digest,
                signature_algorithm,
                signature_key_id,
                signature,
            )

    def get_run(self, run_id: UUID) -> EvaluationRun:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """SELECT payload, payload_sha256, signature_algorithm, signature_key_id,
                          signature_value
                   FROM evaluation_runs WHERE run_id = %s""",
                (run_id,),
            ).fetchone()
        if row is None:
            raise KeyError(str(run_id))
        self._verify_artifact(
            "run",
            run_id,
            row["payload_sha256"],
            row["payload"],
            row["signature_algorithm"],
            row["signature_key_id"],
            row["signature_value"],
        )
        return EvaluationRun.model_validate(row["payload"])

    def list_runs(self, limit: int = 100) -> list[StoredRunSummary]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT run_id, suite_name, dataset_name, dataset_version, agent_version,
                       started_at, completed_at, case_count, hidden_pass_rate
                FROM evaluation_runs ORDER BY completed_at DESC LIMIT %s
                """,
                (limit,),
            ).fetchall()
        return [StoredRunSummary.model_validate(row) for row in rows]

    def save_comparison(
        self, comparison: RunComparison, decision: QualityGateDecision
    ) -> StoredComparison:
        self.initialize()
        artifact = StoredComparison(comparison=comparison, decision=decision)
        payload = artifact.model_dump(mode="json")
        digest = artifact_digest(payload)
        signature_algorithm, signature_key_id, signature = self._sign_artifact(
            "comparison", artifact.comparison_id, digest
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO comparisons (
                    comparison_id, baseline_run_id, candidate_run_id, created_at,
                    outcome, paired_cases, aggregate_pass_rate_delta, payload, payload_sha256,
                    signature_algorithm, signature_key_id, signature_value
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    artifact.comparison_id,
                    comparison.baseline_run_id,
                    comparison.candidate_run_id,
                    artifact.created_at,
                    decision.outcome,
                    comparison.paired_cases,
                    comparison.aggregate_pass_rate_delta,
                    Jsonb(payload),
                    digest,
                    signature_algorithm,
                    signature_key_id,
                    signature,
                ),
            )
            self._append_artifact_ledger(
                connection,
                "comparison",
                artifact.comparison_id,
                digest,
                signature_algorithm,
                signature_key_id,
                signature,
            )
        return artifact

    def get_comparison(self, comparison_id: UUID) -> StoredComparison:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """SELECT payload, payload_sha256, signature_algorithm, signature_key_id,
                          signature_value
                   FROM comparisons WHERE comparison_id = %s""",
                (comparison_id,),
            ).fetchone()
        if row is None:
            raise KeyError(str(comparison_id))
        self._verify_artifact(
            "comparison",
            comparison_id,
            row["payload_sha256"],
            row["payload"],
            row["signature_algorithm"],
            row["signature_key_id"],
            row["signature_value"],
        )
        return StoredComparison.model_validate(row["payload"])

    def register_guardrail_config_version(
        self,
        config_id: str,
        version: str,
        bundle_sha256: str,
        *,
        description: str = "",
        created_by: str = "local-trust",
    ) -> GuardrailConfigVersion:
        config = GuardrailConfigVersion(
            config_id=config_id,
            version=version,
            bundle_sha256=bundle_sha256,
            description=description,
            created_by=created_by,
        )
        self.initialize()
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO guardrail_config_versions (
                        config_id, version, bundle_sha256, description, created_at, created_by
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        config.config_id,
                        config.version,
                        config.bundle_sha256,
                        config.description,
                        config.created_at,
                        config.created_by,
                    ),
                )
        except UniqueViolation as error:
            raise ValueError(
                f"guardrail configuration {config_id}@{version} is already registered"
            ) from error
        return config

    def list_guardrail_config_versions(self) -> list[GuardrailConfigVersion]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                WITH latest AS (
                    SELECT DISTINCT ON (config_id) config_id, version
                    FROM guardrail_config_activations
                    ORDER BY config_id, activation_sequence DESC
                )
                SELECT versions.config_id, versions.version, versions.bundle_sha256,
                       versions.description, versions.created_at, versions.created_by,
                       coalesce(latest.version = versions.version, false) AS active
                FROM guardrail_config_versions AS versions
                LEFT JOIN latest USING (config_id)
                ORDER BY versions.config_id, versions.created_at DESC, versions.version
                """
            ).fetchall()
        return [GuardrailConfigVersion.model_validate(row) for row in rows]

    def get_guardrail_config_version(self, config_id: str, version: str) -> GuardrailConfigVersion:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT versions.config_id, versions.version, versions.bundle_sha256,
                       versions.description, versions.created_at, versions.created_by,
                       coalesce(latest.version = versions.version, false) AS active
                FROM guardrail_config_versions AS versions
                LEFT JOIN LATERAL (
                    SELECT activation.version
                    FROM guardrail_config_activations AS activation
                    WHERE activation.config_id = versions.config_id
                    ORDER BY activation.activation_sequence DESC
                    LIMIT 1
                ) AS latest ON true
                WHERE versions.config_id = %s AND versions.version = %s
                """,
                (config_id, version),
            ).fetchone()
        if row is None:
            raise KeyError(f"{config_id}@{version}")
        return GuardrailConfigVersion.model_validate(row)

    def get_active_guardrail_config(self, config_id: str) -> GuardrailConfigActivation | None:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT activation.activation_id, activation.config_id, activation.version,
                       versions.bundle_sha256, activation.activated_at, activation.activated_by
                FROM guardrail_config_activations AS activation
                JOIN guardrail_config_versions AS versions USING (config_id, version)
                WHERE activation.config_id = %s
                ORDER BY activation.activation_sequence DESC
                LIMIT 1
                """,
                (config_id,),
            ).fetchone()
        return GuardrailConfigActivation.model_validate(row) if row is not None else None

    def activate_guardrail_config(
        self, config_id: str, version: str, *, activated_by: str = "local-trust"
    ) -> GuardrailConfigActivation:
        self.initialize()
        with self._connect() as connection:
            registered = connection.execute(
                """SELECT bundle_sha256 FROM guardrail_config_versions
                   WHERE config_id = %s AND version = %s FOR SHARE""",
                (config_id, version),
            ).fetchone()
            if registered is None:
                raise KeyError(f"{config_id}@{version}")
            activation = GuardrailConfigActivation(
                config_id=config_id,
                version=version,
                bundle_sha256=str(registered["bundle_sha256"]),
                activated_by=activated_by,
            )
            connection.execute(
                """
                INSERT INTO guardrail_config_activations (
                    activation_id, config_id, version, activated_at, activated_by
                ) VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    activation.activation_id,
                    activation.config_id,
                    activation.version,
                    activation.activated_at,
                    activation.activated_by,
                ),
            )
        return activation

    def list_guardrail_config_activations(
        self, config_id: str | None = None, limit: int = 100
    ) -> list[GuardrailConfigActivation]:
        self.initialize()
        where = sql.SQL("WHERE activation.config_id = %s") if config_id is not None else sql.SQL("")
        parameters: tuple[object, ...] = (config_id, limit) if config_id is not None else (limit,)
        with self._connect() as connection:
            rows = connection.execute(
                sql.SQL(
                    """
                SELECT activation.activation_id, activation.config_id, activation.version,
                       versions.bundle_sha256, activation.activated_at, activation.activated_by
                FROM guardrail_config_activations AS activation
                JOIN guardrail_config_versions AS versions USING (config_id, version)
                {}
                ORDER BY activation.activation_sequence DESC
                LIMIT %s
                """
                ).format(where),
                parameters,
            ).fetchall()
        return [GuardrailConfigActivation.model_validate(row) for row in rows]

    def save_guardrail_evidence(self, evidence: GuardrailEvidence) -> StoredGuardrailEvidence:
        self.initialize()
        artifact = StoredGuardrailEvidence(evidence=evidence)
        payload = artifact.model_dump(mode="json")
        digest = artifact_digest(payload)
        signature_algorithm, signature_key_id, signature = self._sign_artifact(
            "guardrail_evidence", artifact.evidence_id, digest
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO guardrail_evidence (
                    evidence_id, created_at, config_id, config_version, model, passed_through,
                    expected_action, payload, payload_sha256, signature_algorithm,
                    signature_key_id, signature_value
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    artifact.evidence_id,
                    artifact.created_at,
                    evidence.config_id,
                    evidence.config_version,
                    evidence.model,
                    evidence.passed_through,
                    evidence.expected_action,
                    Jsonb(payload),
                    digest,
                    signature_algorithm,
                    signature_key_id,
                    signature,
                ),
            )
            self._append_artifact_ledger(
                connection,
                "guardrail_evidence",
                artifact.evidence_id,
                digest,
                signature_algorithm,
                signature_key_id,
                signature,
            )
        return artifact

    def get_guardrail_evidence(self, evidence_id: UUID) -> StoredGuardrailEvidence:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """SELECT payload, payload_sha256, signature_algorithm, signature_key_id,
                          signature_value
                   FROM guardrail_evidence WHERE evidence_id = %s""",
                (evidence_id,),
            ).fetchone()
        if row is None:
            raise KeyError(str(evidence_id))
        self._verify_artifact(
            "guardrail_evidence",
            evidence_id,
            row["payload_sha256"],
            row["payload"],
            row["signature_algorithm"],
            row["signature_key_id"],
            row["signature_value"],
        )
        return StoredGuardrailEvidence.model_validate(row["payload"])

    def list_guardrail_evidence(self, limit: int = 100) -> list[StoredGuardrailEvidenceSummary]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT evidence_id, created_at, config_id, config_version, model, passed_through,
                       expected_action
                FROM guardrail_evidence ORDER BY created_at DESC LIMIT %s
                """,
                (limit,),
            ).fetchall()
        return [StoredGuardrailEvidenceSummary.model_validate(row) for row in rows]

    def guardrail_efficacy_report(
        self,
        *,
        config_id: str | None = None,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
    ) -> GuardrailEfficacyReport:
        self.initialize()
        resolved_end = window_end or datetime.now(UTC)
        resolved_start = window_start or resolved_end - timedelta(days=30)
        if resolved_start.tzinfo is None or resolved_end.tzinfo is None:
            raise ValueError("efficacy timestamps must include a timezone")
        if resolved_start >= resolved_end:
            raise ValueError("efficacy window start must be before window end")
        if resolved_end - resolved_start > timedelta(days=366):
            raise ValueError("efficacy windows cannot exceed 366 days")
        where: sql.Composable = sql.SQL("created_at >= %s AND created_at < %s")
        parameters: tuple[object, ...] = (resolved_start, resolved_end)
        if config_id is not None:
            where += sql.SQL(" AND config_id = %s")
            parameters += (config_id,)
        with self._connect() as connection:
            rows = connection.execute(
                sql.SQL(
                    """
                    SELECT evidence_id, payload, payload_sha256, signature_algorithm,
                           signature_key_id, signature_value
                    FROM guardrail_evidence
                    WHERE {}
                    ORDER BY created_at
                    """
                ).format(where),
                parameters,
            ).fetchall()
        artifacts: list[StoredGuardrailEvidence] = []
        for row in rows:
            evidence_id = cast(UUID, row["evidence_id"])
            self._verify_artifact(
                "guardrail_evidence",
                evidence_id,
                row["payload_sha256"],
                row["payload"],
                row["signature_algorithm"],
                row["signature_key_id"],
                row["signature_value"],
            )
            artifacts.append(StoredGuardrailEvidence.model_validate(row["payload"]))
        return build_guardrail_efficacy_report(
            artifacts,
            window_start=resolved_start,
            window_end=resolved_end,
            config_id=config_id,
        )

    def verify_artifacts(self) -> ArtifactIntegrityReport:
        self.initialize()
        failures: list[ArtifactIntegrityItem] = []
        checked = 0
        signed = 0
        unsigned = 0
        signature_algorithms: dict[str, int] = {}
        with self._connect() as connection:
            sources: tuple[
                tuple[str, str, Literal["run", "comparison", "guardrail_evidence"]], ...
            ] = (
                ("evaluation_runs", "run_id", "run"),
                ("comparisons", "comparison_id", "comparison"),
                ("guardrail_evidence", "evidence_id", "guardrail_evidence"),
            )
            for table, id_column, artifact_type in sources:
                rows = connection.execute(
                    sql.SQL(
                        "SELECT {}, payload, payload_sha256, signature_algorithm, "
                        "signature_key_id, signature_value FROM {}"
                    ).format(sql.Identifier(id_column), sql.Identifier(table))
                ).fetchall()
                checked += len(rows)
                for row in rows:
                    artifact_id = cast(UUID, row[id_column])
                    actual = artifact_digest(row["payload"])
                    expected = str(row["payload_sha256"])
                    signature_algorithm = row["signature_algorithm"]
                    signature_key_id = row["signature_key_id"]
                    signature = row["signature_value"]
                    is_signed = any(
                        value is not None
                        for value in (signature_algorithm, signature_key_id, signature)
                    )
                    signed += int(is_signed)
                    unsigned += int(not is_signed)
                    if signature_algorithm is not None:
                        algorithm = str(signature_algorithm)
                        signature_algorithms[algorithm] = signature_algorithms.get(algorithm, 0) + 1
                    if not hmac.compare_digest(actual, expected):
                        failures.append(
                            ArtifactIntegrityItem(
                                artifact_type=artifact_type,
                                artifact_id=artifact_id,
                                valid=False,
                                expected_sha256=expected,
                                actual_sha256=actual,
                            )
                        )
                        continue
                    try:
                        self._verify_authenticity(
                            artifact_type,
                            artifact_id,
                            expected,
                            signature_algorithm,
                            signature_key_id,
                            signature,
                        )
                    except ArtifactAuthenticityError as error:
                        failures.append(
                            ArtifactIntegrityItem(
                                artifact_type=artifact_type,
                                artifact_id=artifact_id,
                                valid=False,
                                expected_sha256=expected,
                                actual_sha256=actual,
                                failure_kind=(
                                    "missing_signing_key"
                                    if error.reason == "missing_signing_key"
                                    else "signature"
                                ),
                                signature_algorithm=error.algorithm,
                                signing_key_id=error.signing_key_id,
                            )
                        )
            ledger_checked, ledger_valid, ledger_head, ledger_failures = (
                self._verify_artifact_ledger(connection)
            )
        return ArtifactIntegrityReport(
            checked=checked,
            valid=checked - len(failures),
            signed=signed,
            unsigned=unsigned,
            signature_algorithms=dict(sorted(signature_algorithms.items())),
            ledger_checked=ledger_checked,
            ledger_valid=ledger_valid,
            ledger_head_sha256=ledger_head,
            ledger_failures=ledger_failures,
            failures=failures,
        )

    @staticmethod
    def _verify_artifact_ledger(
        connection: psycopg.Connection[dict[str, object]],
    ) -> tuple[int, int, str, list[ArtifactLedgerFailure]]:
        rows = connection.execute(
            """SELECT sequence, artifact_type, artifact_id, payload_sha256,
                      signature_algorithm, signing_key_id, signature_value,
                      previous_entry_sha256, entry_sha256
               FROM artifact_ledger ORDER BY sequence"""
        ).fetchall()
        failures: list[ArtifactLedgerFailure] = []
        previous = LEDGER_GENESIS_SHA256
        expected_sequence = 1
        source_tables = {
            "run": ("evaluation_runs", "run_id"),
            "comparison": ("comparisons", "comparison_id"),
            "guardrail_evidence": ("guardrail_evidence", "evidence_id"),
        }
        source_envelopes: dict[tuple[str, UUID], tuple[str | None, ...]] = {}
        for artifact_type, (table, id_column) in source_tables.items():
            source_rows = connection.execute(
                sql.SQL(
                    "SELECT {}, payload_sha256, signature_algorithm, signature_key_id, "
                    "signature_value FROM {}"
                ).format(sql.Identifier(id_column), sql.Identifier(table))
            ).fetchall()
            for source in source_rows:
                source_envelopes[(artifact_type, cast(UUID, source[id_column]))] = tuple(
                    str(source[key]) if source[key] is not None else None
                    for key in (
                        "payload_sha256",
                        "signature_algorithm",
                        "signature_key_id",
                        "signature_value",
                    )
                )
        tenant_id = current_tenant_id()
        for row in rows:
            sequence = cast(int, row["sequence"])
            artifact_type = cast(
                Literal["run", "comparison", "guardrail_evidence"],
                str(row["artifact_type"]),
            )
            artifact_id = cast(UUID, row["artifact_id"])
            payload_sha256 = str(row["payload_sha256"])
            signature_algorithm = (
                str(row["signature_algorithm"]) if row["signature_algorithm"] is not None else None
            )
            signing_key_id = (
                str(row["signing_key_id"]) if row["signing_key_id"] is not None else None
            )
            signature = str(row["signature_value"]) if row["signature_value"] is not None else None
            stored_previous = str(row["previous_entry_sha256"])
            stored_entry = str(row["entry_sha256"])
            expected_entry = ledger_entry_digest(
                tenant_id,
                sequence,
                artifact_type,
                artifact_id,
                payload_sha256,
                signature_algorithm,
                signing_key_id,
                signature,
                stored_previous,
            )
            failure: ArtifactLedgerFailure | None = None
            if sequence != expected_sequence:
                failure = ArtifactLedgerFailure(
                    sequence=sequence,
                    artifact_type=artifact_type,
                    artifact_id=artifact_id,
                    reason="sequence_gap",
                )
            elif not hmac.compare_digest(stored_previous, previous):
                failure = ArtifactLedgerFailure(
                    sequence=sequence,
                    artifact_type=artifact_type,
                    artifact_id=artifact_id,
                    reason="previous_hash",
                    expected_sha256=previous,
                    actual_sha256=stored_previous,
                )
            elif not hmac.compare_digest(stored_entry, expected_entry):
                failure = ArtifactLedgerFailure(
                    sequence=sequence,
                    artifact_type=artifact_type,
                    artifact_id=artifact_id,
                    reason="entry_hash",
                    expected_sha256=expected_entry,
                    actual_sha256=stored_entry,
                )
            else:
                source_envelope = source_envelopes.get((artifact_type, artifact_id))
                if source_envelope is None:
                    failure = ArtifactLedgerFailure(
                        sequence=sequence,
                        artifact_type=artifact_type,
                        artifact_id=artifact_id,
                        reason="missing_artifact",
                    )
                elif source_envelope != (
                    payload_sha256,
                    signature_algorithm,
                    signing_key_id,
                    signature,
                ):
                    failure = ArtifactLedgerFailure(
                        sequence=sequence,
                        artifact_type=artifact_type,
                        artifact_id=artifact_id,
                        reason="artifact_mismatch",
                    )
            if failure is not None:
                failures.append(failure)
            previous = stored_entry
            expected_sequence = sequence + 1
        return len(rows), len(rows) - len(failures), previous, failures

    def list_comparisons(self, limit: int = 100) -> list[StoredComparisonSummary]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT comparison_id, baseline_run_id, candidate_run_id, created_at,
                       outcome, paired_cases, aggregate_pass_rate_delta
                FROM comparisons ORDER BY created_at DESC LIMIT %s
                """,
                (limit,),
            ).fetchall()
        return [StoredComparisonSummary.model_validate(row) for row in rows]

    def health(self) -> dict[str, object]:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT version, current_database() AS database FROM schema_metadata LIMIT 1"
            ).fetchone()
        if row is None:
            raise RuntimeError("schema metadata was not initialized")
        return {
            "status": "ok",
            "database": row["database"],
            "schema": self.schema,
            "schema_version": row["version"],
            "connection_mode": self.connection_mode,
        }

    def operational_snapshot(self) -> OperationalSnapshot:
        self.initialize()
        with self._connect() as connection:
            runs_total = connection.execute(
                "SELECT count(*) AS value FROM evaluation_runs"
            ).fetchone()
            comparisons_total = connection.execute(
                "SELECT count(*) AS value FROM comparisons"
            ).fetchone()
            guardrail_row = connection.execute(
                """
                SELECT count(*) AS total,
                       count(*) FILTER (WHERE NOT passed_through) AS interventions
                FROM guardrail_evidence
                """
            ).fetchone()
            job_rows = connection.execute(
                "SELECT status, count(*) AS value FROM evaluation_jobs GROUP BY status"
            ).fetchall()
            gate_rows = connection.execute(
                "SELECT outcome, count(*) AS value FROM comparisons GROUP BY outcome"
            ).fetchall()
            worker_row = connection.execute(
                """
                SELECT count(*) AS registered,
                       count(*) FILTER (WHERE last_seen_at >= now() - interval '2 minutes') AS active
                FROM workers
                """
            ).fetchone()
            queue_row = connection.execute(
                """
                SELECT count(*) FILTER (
                           WHERE status = 'running' AND lease_expires_at < now()
                       ) AS expired_leases,
                       coalesce(extract(epoch FROM now() - min(created_at) FILTER (
                           WHERE status = 'queued'
                       )), 0) AS oldest_queued_seconds,
                       coalesce(avg(extract(epoch FROM updated_at - created_at)) FILTER (
                           WHERE status = 'completed'
                       ), 0) AS average_completed_job_seconds
                FROM evaluation_jobs
                """
            ).fetchone()
        if (
            runs_total is None
            or comparisons_total is None
            or guardrail_row is None
            or worker_row is None
            or queue_row is None
        ):
            raise RuntimeError("PostgreSQL did not return operational metrics")
        return OperationalSnapshot(
            runs_total=int(str(runs_total["value"])),
            comparisons_total=int(str(comparisons_total["value"])),
            guardrail_evidence_total=int(str(guardrail_row["total"])),
            guardrail_interventions_total=int(str(guardrail_row["interventions"])),
            job_counts={str(row["status"]): int(str(row["value"])) for row in job_rows},
            gate_counts={str(row["outcome"]): int(str(row["value"])) for row in gate_rows},
            workers_registered=int(str(worker_row["registered"])),
            workers_active=int(str(worker_row["active"])),
            expired_leases=int(str(queue_row["expired_leases"])),
            oldest_queued_seconds=float(str(queue_row["oldest_queued_seconds"])),
            average_completed_job_seconds=float(str(queue_row["average_completed_job_seconds"])),
        )

    def enqueue_job(
        self,
        suite_path: str,
        agent_version: str,
        priority: int = 0,
        max_attempts: int = 3,
        required_accelerator: Accelerator = Accelerator.CPU,
        required_labels: dict[str, str] | None = None,
        minimum_gpu_memory_mb: int = 0,
        minimum_cuda_compute_capability: float | None = None,
        minimum_gpu_memory_available_mb: int = 0,
        maximum_gpu_utilization_percent: float | None = None,
        required_mig_profile: str | None = None,
        traceparent: str | None = None,
        request_id: str | None = None,
    ) -> EvaluationJob:
        effective_labels = dict(required_labels or {})
        if agent_version.startswith("ollama/"):
            runtime_label = effective_labels.setdefault("runtime", "ollama")
            if runtime_label != "ollama":
                raise ValueError("Ollama jobs require the runtime=ollama label")
        if agent_version.startswith("openai/"):
            runtime_label = effective_labels.setdefault("runtime", "openai-compatible")
            if runtime_label != "openai-compatible":
                raise ValueError(
                    "OpenAI-compatible jobs require the runtime=openai-compatible label"
                )
        if agent_version.startswith("nim/"):
            runtime_label = effective_labels.setdefault("runtime", "nvidia-nim")
            if runtime_label != "nvidia-nim":
                raise ValueError("NVIDIA NIM jobs require the runtime=nvidia-nim label")
        job = EvaluationJob(
            suite_path=suite_path,
            agent_version=agent_version,
            priority=priority,
            max_attempts=max_attempts,
            required_accelerator=required_accelerator,
            required_labels=effective_labels,
            minimum_gpu_memory_mb=minimum_gpu_memory_mb,
            minimum_cuda_compute_capability=minimum_cuda_compute_capability,
            minimum_gpu_memory_available_mb=minimum_gpu_memory_available_mb,
            maximum_gpu_utilization_percent=maximum_gpu_utilization_percent,
            required_mig_profile=required_mig_profile,
            traceparent=traceparent,
            request_id=request_id,
        )
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                INSERT INTO evaluation_jobs (
                    job_id, suite_path, agent_version, status, priority, attempts,
                    max_attempts, created_at, updated_at, required_accelerator, required_labels,
                    minimum_gpu_memory_mb, minimum_cuda_compute_capability,
                    minimum_gpu_memory_available_mb, maximum_gpu_utilization_percent,
                    required_mig_profile, traceparent, request_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                (
                    job.job_id,
                    job.suite_path,
                    job.agent_version,
                    job.status.value,
                    job.priority,
                    job.attempts,
                    job.max_attempts,
                    job.created_at,
                    job.updated_at,
                    job.required_accelerator.value,
                    Jsonb(job.required_labels),
                    job.minimum_gpu_memory_mb,
                    job.minimum_cuda_compute_capability,
                    job.minimum_gpu_memory_available_mb,
                    job.maximum_gpu_utilization_percent,
                    job.required_mig_profile,
                    job.traceparent,
                    job.request_id,
                ),
            ).fetchone()
        if row is None:
            raise RuntimeError("PostgreSQL did not return the queued job")
        return EvaluationJob.model_validate(row)

    def get_job(self, job_id: UUID) -> EvaluationJob:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM evaluation_jobs WHERE job_id = %s", (job_id,)
            ).fetchone()
        if row is None:
            raise KeyError(str(job_id))
        return EvaluationJob.model_validate(row)

    def list_jobs(self, limit: int = 100, status: JobStatus | None = None) -> list[EvaluationJob]:
        self.initialize()
        query = "SELECT * FROM evaluation_jobs"
        parameters: tuple[object, ...]
        if status is None:
            parameters = (limit,)
        else:
            query += " WHERE status = %s"
            parameters = (status.value, limit)
        query += " ORDER BY created_at DESC LIMIT %s"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [EvaluationJob.model_validate(row) for row in rows]

    def placement_diagnostic(self, job_id: UUID) -> JobPlacementDiagnostic:
        return diagnose_placement(self.get_job(job_id), self.list_workers())

    def gpu_capacity_forecast(
        self, workers: list[WorkerRecord] | None = None
    ) -> GpuCapacityForecast:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT * FROM evaluation_jobs
                   WHERE status = 'queued' AND required_accelerator = 'cuda'
                   ORDER BY priority DESC, created_at, job_id"""
            ).fetchall()
        jobs = [EvaluationJob.model_validate(row) for row in rows]
        return forecast_gpu_capacity(
            jobs,
            workers if workers is not None else self.list_workers(),
            duration_estimates=self._gpu_duration_estimates(),
        )

    def _gpu_duration_estimates(self) -> list[GpuDurationEstimate]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                WITH recent_durations AS (
                    SELECT required_mig_profile,
                           extract(epoch FROM updated_at - started_at) AS duration_seconds
                    FROM evaluation_jobs
                    WHERE status = 'completed'
                      AND required_accelerator = 'cuda'
                      AND started_at IS NOT NULL
                      AND updated_at > started_at
                    ORDER BY updated_at DESC
                    LIMIT 500
                )
                SELECT NULL::text AS mig_profile,
                       count(*) AS sample_count,
                       avg(duration_seconds) AS average_seconds,
                       percentile_cont(0.9) WITHIN GROUP (
                           ORDER BY duration_seconds
                       ) AS p90_seconds
                FROM recent_durations
                HAVING count(*) > 0
                UNION ALL
                SELECT required_mig_profile AS mig_profile,
                       count(*) AS sample_count,
                       avg(duration_seconds) AS average_seconds,
                       percentile_cont(0.9) WITHIN GROUP (
                           ORDER BY duration_seconds
                       ) AS p90_seconds
                FROM recent_durations
                WHERE required_mig_profile IS NOT NULL
                GROUP BY required_mig_profile
                ORDER BY mig_profile NULLS FIRST
                """
            ).fetchall()
        return [GpuDurationEstimate.model_validate(row) for row in rows]

    def gpu_demand_forecast(
        self,
        workers: list[WorkerRecord] | None = None,
        *,
        now: datetime | None = None,
    ) -> GpuDemandForecast:
        self.initialize()
        observed_at = now or datetime.now(UTC)
        lookback_start = observed_at - timedelta(days=DEFAULT_LOOKBACK_DAYS)
        with self._connect() as connection:
            inception = connection.execute(
                sql.SQL("SELECT min(created_at) AS history_start FROM {}.evaluation_jobs").format(
                    sql.Identifier(self.schema)
                )
            ).fetchone()
            stored_start = cast(datetime | None, inception["history_start"] if inception else None)
            history_start = max(stored_start or lookback_start, lookback_start)
            rows = connection.execute(
                sql.SQL(
                    """SELECT date_trunc('hour', created_at) AS hour_start,
                              count(*) AS arrivals
                       FROM {}.evaluation_jobs
                       WHERE required_accelerator = 'cuda'
                         AND created_at >= %s AND created_at < %s
                       GROUP BY hour_start ORDER BY hour_start"""
                ).format(sql.Identifier(self.schema)),
                (history_start, observed_at),
            ).fetchall()
            backlog = connection.execute(
                sql.SQL(
                    """SELECT count(*) FILTER (WHERE status = 'queued') AS queued,
                              count(*) FILTER (WHERE status = 'running') AS running
                       FROM {}.evaluation_jobs
                       WHERE required_accelerator = 'cuda'
                         AND status IN ('queued', 'running')"""
                ).format(sql.Identifier(self.schema))
            ).fetchone()
        estimates = self._gpu_duration_estimates()
        all_cuda = next((item for item in estimates if item.mig_profile is None), None)
        worker_inventory = workers if workers is not None else self.list_workers()
        active_after = observed_at - timedelta(seconds=DEFAULT_WORKER_ACTIVE_SECONDS)
        active_cuda_workers = sum(
            worker.last_seen_at >= active_after
            and Accelerator.CUDA in worker.capabilities.accelerators
            for worker in worker_inventory
        )
        return forecast_gpu_demand(
            [(cast(datetime, row["hour_start"]), cast(int, row["arrivals"])) for row in rows],
            history_start=history_start,
            observed_at=observed_at,
            current_queued_cuda_jobs=cast(int, backlog["queued"] if backlog else 0),
            current_running_cuda_jobs=cast(int, backlog["running"] if backlog else 0),
            active_cuda_workers=active_cuda_workers,
            duration_estimate=all_cuda,
        )

    def lease_job(
        self,
        worker_id: str,
        lease_seconds: int = 900,
        capabilities: WorkerCapabilities | None = None,
    ) -> EvaluationJob | None:
        self.initialize()
        accelerators = [Accelerator.CPU.value]
        labels: dict[str, str] = {}
        gpu_profiles: list[dict[str, int | float | str | None]] = []
        if capabilities is not None:
            accelerators = [item.value for item in capabilities.accelerators]
            labels = capabilities.labels
            for gpu in capabilities.gpus:
                try:
                    compute_capability: float | None = float(gpu.compute_capability)
                except ValueError:
                    compute_capability = None
                gpu_profiles.append(
                    {
                        "memory_total_mb": gpu.memory_total_mb,
                        "memory_used_mb": gpu.memory_used_mb,
                        "compute_capability": compute_capability,
                        "utilization_percent": gpu.utilization_percent,
                        "mig_profile": gpu.mig_profile,
                    }
                )
        with self._connect() as connection:
            row = connection.execute(
                """
                WITH claimable AS (
                    SELECT job_id
                    FROM evaluation_jobs
                    WHERE attempts < max_attempts
                      AND required_accelerator = ANY(%s)
                      AND %s::jsonb @> required_labels
                      AND (
                        (
                          minimum_gpu_memory_mb = 0
                          AND minimum_cuda_compute_capability IS NULL
                          AND minimum_gpu_memory_available_mb = 0
                          AND maximum_gpu_utilization_percent IS NULL
                          AND required_mig_profile IS NULL
                        )
                        OR EXISTS (
                          SELECT 1
                          FROM jsonb_to_recordset(%s::jsonb)
                            AS gpu(
                              memory_total_mb INTEGER,
                              memory_used_mb INTEGER,
                              compute_capability DOUBLE PRECISION,
                              utilization_percent DOUBLE PRECISION,
                              mig_profile TEXT
                            )
                          WHERE gpu.memory_total_mb >= minimum_gpu_memory_mb
                            AND (
                              minimum_cuda_compute_capability IS NULL
                              OR gpu.compute_capability >= minimum_cuda_compute_capability
                            )
                            AND (
                              minimum_gpu_memory_available_mb = 0
                              OR (
                                gpu.memory_used_mb IS NOT NULL
                                AND greatest(0, gpu.memory_total_mb - gpu.memory_used_mb)
                                  >= minimum_gpu_memory_available_mb
                              )
                            )
                            AND (
                              maximum_gpu_utilization_percent IS NULL
                              OR (
                                gpu.utilization_percent IS NOT NULL
                                AND gpu.utilization_percent <= maximum_gpu_utilization_percent
                              )
                            )
                            AND (
                              required_mig_profile IS NULL
                              OR gpu.mig_profile = required_mig_profile
                            )
                        )
                      )
                      AND (
                        status = 'queued'
                        OR (status = 'running' AND lease_expires_at < now())
                      )
                    ORDER BY priority DESC, created_at
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )
                UPDATE evaluation_jobs AS jobs
                SET status = 'running',
                    attempts = jobs.attempts + 1,
                    started_at = now(),
                    lease_owner = %s,
                    lease_expires_at = now() + (%s * interval '1 second'),
                    updated_at = now(),
                    error = NULL
                FROM claimable
                WHERE jobs.job_id = claimable.job_id
                RETURNING jobs.*
                """,
                (accelerators, Jsonb(labels), Jsonb(gpu_profiles), worker_id, lease_seconds),
            ).fetchone()
        return EvaluationJob.model_validate(row) if row is not None else None

    def register_worker(self, worker_id: str, capabilities: WorkerCapabilities) -> WorkerRecord:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                INSERT INTO workers (worker_id, capabilities, registered_at, last_seen_at)
                VALUES (%s, %s, now(), now())
                ON CONFLICT(tenant_id, worker_id) DO UPDATE SET
                    capabilities = excluded.capabilities, last_seen_at = now()
                RETURNING *
                """,
                (worker_id, Jsonb(capabilities.model_dump(mode="json"))),
            ).fetchone()
        if row is None:
            raise RuntimeError("PostgreSQL did not return the registered worker")
        return WorkerRecord.model_validate(row)

    def list_workers(self) -> list[WorkerRecord]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM workers ORDER BY last_seen_at DESC").fetchall()
        return [WorkerRecord.model_validate(row) for row in rows]

    def renew_job_lease(
        self, job_id: UUID, worker_id: str, lease_seconds: int = 900
    ) -> EvaluationJob:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                UPDATE evaluation_jobs
                SET lease_expires_at = now() + (%s * interval '1 second'), updated_at = now()
                WHERE job_id = %s AND status = 'running' AND lease_owner = %s
                RETURNING *
                """,
                (lease_seconds, job_id, worker_id),
            ).fetchone()
        return self._leased_job_or_error(row, job_id)

    def complete_job(self, job_id: UUID, worker_id: str, run_id: UUID) -> EvaluationJob:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                UPDATE evaluation_jobs
                SET status = 'completed', run_id = %s, updated_at = now(),
                    lease_owner = NULL, lease_expires_at = NULL, error = NULL
                WHERE job_id = %s AND status = 'running' AND lease_owner = %s
                RETURNING *
                """,
                (run_id, job_id, worker_id),
            ).fetchone()
        return self._leased_job_or_error(row, job_id)

    def fail_job(self, job_id: UUID, worker_id: str, error: str) -> EvaluationJob:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                UPDATE evaluation_jobs
                SET status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'queued' END,
                    updated_at = now(), started_at = CASE
                        WHEN attempts >= max_attempts THEN started_at ELSE NULL END,
                    lease_owner = NULL, lease_expires_at = NULL, error = %s
                WHERE job_id = %s AND status = 'running' AND lease_owner = %s
                RETURNING *
                """,
                (error[:4000], job_id, worker_id),
            ).fetchone()
        return self._leased_job_or_error(row, job_id)

    def cancel_job(self, job_id: UUID) -> EvaluationJob:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                UPDATE evaluation_jobs
                SET status = 'cancelled', updated_at = now(),
                    lease_owner = NULL, lease_expires_at = NULL
                WHERE job_id = %s AND status IN ('queued', 'running')
                RETURNING *
                """,
                (job_id,),
            ).fetchone()
        if row is None:
            existing = self.get_job(job_id)
            msg = f"job in {existing.status} state cannot be cancelled"
            raise ValueError(msg)
        return EvaluationJob.model_validate(row)

    @staticmethod
    def _leased_job_or_error(row: dict[str, object] | None, job_id: UUID) -> EvaluationJob:
        if row is None:
            msg = f"worker no longer owns the lease for job {job_id}"
            raise RuntimeError(msg)
        return EvaluationJob.model_validate(row)

    def _verify_artifact(
        self,
        artifact_type: str,
        artifact_id: UUID,
        expected_value: object,
        payload: object,
        signature_algorithm: object,
        signing_key_id: object,
        signature: object,
    ) -> None:
        expected = str(expected_value)
        actual = artifact_digest(payload)
        if not hmac.compare_digest(actual, expected):
            raise ArtifactIntegrityError(artifact_type, artifact_id, expected, actual)
        self._verify_authenticity(
            artifact_type,
            artifact_id,
            expected,
            signature_algorithm,
            signing_key_id,
            signature,
        )

    def _verify_authenticity(
        self,
        artifact_type: str,
        artifact_id: UUID,
        payload_sha256: str,
        signature_algorithm_value: object,
        signing_key_id_value: object,
        signature_value: object,
    ) -> None:
        if (
            signature_algorithm_value is None
            and signing_key_id_value is None
            and signature_value is None
        ):
            return
        signature_algorithm = (
            str(signature_algorithm_value) if signature_algorithm_value is not None else None
        )
        signing_key_id = str(signing_key_id_value) if signing_key_id_value is not None else None
        if signature_algorithm is None or signing_key_id is None or signature_value is None:
            raise ArtifactAuthenticityError(
                artifact_type,
                artifact_id,
                signing_key_id,
                "incomplete_signature",
                signature_algorithm,
            )
        if self.keyring is None:
            raise ArtifactAuthenticityError(
                artifact_type,
                artifact_id,
                signing_key_id,
                "missing_signing_key",
                signature_algorithm,
            )
        try:
            valid = self.keyring.verify(
                signature_algorithm,
                signing_key_id,
                artifact_type,
                artifact_id,
                payload_sha256,
                str(signature_value),
            )
        except KeyError as error:
            raise ArtifactAuthenticityError(
                artifact_type,
                artifact_id,
                signing_key_id,
                "missing_signing_key",
                signature_algorithm,
            ) from error
        except ValueError as error:
            raise ArtifactAuthenticityError(
                artifact_type, artifact_id, signing_key_id, "signature", signature_algorithm
            ) from error
        if not valid:
            raise ArtifactAuthenticityError(
                artifact_type, artifact_id, signing_key_id, "signature", signature_algorithm
            )

    def _sign_artifact(
        self, artifact_type: str, artifact_id: UUID, payload_sha256: str
    ) -> tuple[str | None, str | None, str | None]:
        if self.keyring is None:
            return None, None, None
        signature = self.keyring.sign(artifact_type, artifact_id, payload_sha256)
        return (
            self.keyring.active_algorithm,
            self.keyring.active_key_id,
            signature,
        )

    @staticmethod
    def _migrate_signature_envelopes(
        connection: psycopg.Connection[dict[str, object]],
    ) -> None:
        for table in SIGNED_ARTIFACT_TABLES:
            connection.execute(
                sql.SQL(
                    "UPDATE {} SET signature_algorithm = %s, "
                    "signature_value = signature_hmac_sha256 "
                    "WHERE signature_algorithm IS NULL AND signature_value IS NULL "
                    "AND signature_key_id IS NOT NULL AND signature_hmac_sha256 IS NOT NULL"
                ).format(sql.Identifier(table)),
                (HMAC_SHA256,),
            )

    @staticmethod
    def _suspend_tenant_isolation(
        connection: psycopg.Connection[dict[str, object]],
    ) -> None:
        for table in TENANT_TABLES:
            connection.execute(
                sql.SQL("ALTER TABLE {} NO FORCE ROW LEVEL SECURITY").format(sql.Identifier(table))
            )

    @staticmethod
    def _install_ledger_immutability_trigger(
        connection: psycopg.Connection[dict[str, object]],
    ) -> None:
        connection.execute(
            """
            CREATE OR REPLACE FUNCTION reject_artifact_ledger_mutation()
            RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'artifact ledger is append-only';
            END;
            $$
            """
        )
        connection.execute("DROP TRIGGER IF EXISTS artifact_ledger_append_only ON artifact_ledger")
        connection.execute(
            """CREATE TRIGGER artifact_ledger_append_only
               BEFORE UPDATE OR DELETE ON artifact_ledger
               FOR EACH ROW EXECUTE FUNCTION reject_artifact_ledger_mutation()"""
        )

    def _backfill_artifact_ledger(self, connection: psycopg.Connection[dict[str, object]]) -> None:
        rows = connection.execute(
            """
            SELECT tenant_id, artifact_type, artifact_id, payload_sha256,
                   signature_algorithm, signing_key_id, signature_value
            FROM (
                SELECT tenant_id, 'run' AS artifact_type, run_id AS artifact_id,
                       payload_sha256, signature_algorithm,
                       signature_key_id AS signing_key_id, signature_value,
                       completed_at AS event_at
                FROM evaluation_runs
                UNION ALL
                SELECT tenant_id, 'comparison', comparison_id, payload_sha256,
                       signature_algorithm, signature_key_id AS signing_key_id,
                       signature_value, created_at
                FROM comparisons
                UNION ALL
                SELECT tenant_id, 'guardrail_evidence', evidence_id, payload_sha256,
                       signature_algorithm, signature_key_id AS signing_key_id,
                       signature_value, created_at
                FROM guardrail_evidence
            ) AS artifacts
            ORDER BY tenant_id, event_at, artifact_type, artifact_id
            """
        ).fetchall()
        for row in rows:
            self._append_ledger_values(
                connection,
                str(row["tenant_id"]),
                str(row["artifact_type"]),
                cast(UUID, row["artifact_id"]),
                str(row["payload_sha256"]),
                str(row["signature_algorithm"]) if row["signature_algorithm"] is not None else None,
                str(row["signing_key_id"]) if row["signing_key_id"] is not None else None,
                str(row["signature_value"]) if row["signature_value"] is not None else None,
                require_match=False,
            )

    def _append_artifact_ledger(
        self,
        connection: psycopg.Connection[dict[str, object]],
        artifact_type: str,
        artifact_id: UUID,
        payload_sha256: str,
        signature_algorithm: str | None,
        signing_key_id: str | None,
        signature: str | None,
    ) -> None:
        tenant_id = current_tenant_id()
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"{self.schema}:{tenant_id}:artifact-ledger",),
        )
        self._append_ledger_values(
            connection,
            tenant_id,
            artifact_type,
            artifact_id,
            payload_sha256,
            signature_algorithm,
            signing_key_id,
            signature,
        )

    @staticmethod
    def _append_ledger_values(
        connection: psycopg.Connection[dict[str, object]],
        tenant_id: str,
        artifact_type: str,
        artifact_id: UUID,
        payload_sha256: str,
        signature_algorithm: str | None,
        signing_key_id: str | None,
        signature: str | None,
        *,
        require_match: bool = True,
    ) -> None:
        existing = connection.execute(
            """SELECT payload_sha256, signature_algorithm, signing_key_id, signature_value
               FROM artifact_ledger
               WHERE tenant_id = %s AND artifact_type = %s AND artifact_id = %s""",
            (tenant_id, artifact_type, artifact_id),
        ).fetchone()
        envelope = (payload_sha256, signature_algorithm, signing_key_id, signature)
        if existing is not None:
            persisted = (
                str(existing["payload_sha256"]),
                str(existing["signature_algorithm"])
                if existing["signature_algorithm"] is not None
                else None,
                str(existing["signing_key_id"]) if existing["signing_key_id"] is not None else None,
                str(existing["signature_value"])
                if existing["signature_value"] is not None
                else None,
            )
            if require_match and persisted != envelope:
                raise RuntimeError(f"artifact ledger conflict for {artifact_type} {artifact_id}")
            return
        latest = connection.execute(
            """SELECT sequence, entry_sha256 FROM artifact_ledger
               WHERE tenant_id = %s ORDER BY sequence DESC LIMIT 1""",
            (tenant_id,),
        ).fetchone()
        sequence = cast(int, latest["sequence"]) + 1 if latest is not None else 1
        previous = str(latest["entry_sha256"]) if latest is not None else LEDGER_GENESIS_SHA256
        entry_sha256 = ledger_entry_digest(
            tenant_id,
            sequence,
            artifact_type,
            artifact_id,
            payload_sha256,
            signature_algorithm,
            signing_key_id,
            signature,
            previous,
        )
        connection.execute(
            """INSERT INTO artifact_ledger (
                   tenant_id, sequence, artifact_type, artifact_id, payload_sha256,
                   signature_algorithm, signing_key_id, signature_value,
                   previous_entry_sha256, entry_sha256
               ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                tenant_id,
                sequence,
                artifact_type,
                artifact_id,
                payload_sha256,
                signature_algorithm,
                signing_key_id,
                signature,
                previous,
                entry_sha256,
            ),
        )

    def _enable_tenant_isolation(self, connection: psycopg.Connection[dict[str, object]]) -> None:
        for table in TENANT_TABLES:
            identifier = sql.Identifier(table)
            connection.execute(
                sql.SQL("ALTER TABLE {} ADD COLUMN IF NOT EXISTS tenant_id TEXT").format(identifier)
            )
            connection.execute(
                sql.SQL("UPDATE {} SET tenant_id = 'default' WHERE tenant_id IS NULL").format(
                    identifier
                )
            )
            connection.execute(
                sql.SQL(
                    "ALTER TABLE {} ALTER COLUMN tenant_id SET DEFAULT "
                    "current_setting('aecontrol.tenant_id')"
                ).format(identifier)
            )
            connection.execute(
                sql.SQL("ALTER TABLE {} ALTER COLUMN tenant_id SET NOT NULL").format(identifier)
            )
            self._add_constraint_if_missing(
                connection,
                table,
                f"{table}_tenant_id_check",
                "CHECK (tenant_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$')",
            )
            connection.execute(
                sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(identifier)
            )
            connection.execute(
                sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY").format(identifier)
            )
            connection.execute(
                sql.SQL("DROP POLICY IF EXISTS tenant_isolation ON {}").format(identifier)
            )
            connection.execute(
                sql.SQL(
                    "CREATE POLICY tenant_isolation ON {} "
                    "USING (tenant_id = current_setting('aecontrol.tenant_id', true)) "
                    "WITH CHECK (tenant_id = current_setting('aecontrol.tenant_id', true))"
                ).format(identifier)
            )
            connection.execute(
                sql.SQL("CREATE INDEX IF NOT EXISTS {} ON {} (tenant_id)").format(
                    sql.Identifier(f"idx_{table}_tenant"), identifier
                )
            )

        self._add_constraint_if_missing(
            connection,
            "evaluation_runs",
            "evaluation_runs_tenant_run_key",
            "UNIQUE (tenant_id, run_id)",
        )
        connection.execute(
            "ALTER TABLE comparisons DROP CONSTRAINT IF EXISTS comparisons_baseline_run_id_fkey"
        )
        connection.execute(
            "ALTER TABLE comparisons DROP CONSTRAINT IF EXISTS comparisons_candidate_run_id_fkey"
        )
        self._add_constraint_if_missing(
            connection,
            "comparisons",
            "comparisons_tenant_baseline_run_fkey",
            "FOREIGN KEY (tenant_id, baseline_run_id) "
            "REFERENCES evaluation_runs(tenant_id, run_id)",
        )
        self._add_constraint_if_missing(
            connection,
            "comparisons",
            "comparisons_tenant_candidate_run_fkey",
            "FOREIGN KEY (tenant_id, candidate_run_id) "
            "REFERENCES evaluation_runs(tenant_id, run_id)",
        )
        connection.execute(
            "ALTER TABLE evaluation_jobs DROP CONSTRAINT IF EXISTS evaluation_jobs_run_id_fkey"
        )
        self._add_constraint_if_missing(
            connection,
            "evaluation_jobs",
            "evaluation_jobs_tenant_run_fkey",
            "FOREIGN KEY (tenant_id, run_id) REFERENCES evaluation_runs(tenant_id, run_id)",
        )

        connection.execute(
            "ALTER TABLE guardrail_config_activations DROP CONSTRAINT IF EXISTS "
            "guardrail_config_activations_config_id_version_fkey"
        )
        if self._constraint_exists(
            connection, "guardrail_config_versions", "guardrail_config_versions_pkey"
        ):
            connection.execute(
                "ALTER TABLE guardrail_config_versions "
                "DROP CONSTRAINT guardrail_config_versions_pkey"
            )
        self._add_constraint_if_missing(
            connection,
            "guardrail_config_versions",
            "guardrail_config_versions_tenant_pkey",
            "PRIMARY KEY (tenant_id, config_id, version)",
        )
        self._add_constraint_if_missing(
            connection,
            "guardrail_config_activations",
            "guardrail_config_activations_tenant_version_fkey",
            "FOREIGN KEY (tenant_id, config_id, version) "
            "REFERENCES guardrail_config_versions(tenant_id, config_id, version)",
        )

        if self._constraint_exists(connection, "workers", "workers_pkey"):
            connection.execute("ALTER TABLE workers DROP CONSTRAINT workers_pkey")
        self._add_constraint_if_missing(
            connection,
            "workers",
            "workers_tenant_pkey",
            "PRIMARY KEY (tenant_id, worker_id)",
        )

    @staticmethod
    def _constraint_exists(
        connection: psycopg.Connection[dict[str, object]], table: str, name: str
    ) -> bool:
        return (
            connection.execute(
                """SELECT 1 FROM pg_constraint
                   WHERE conrelid = %s::regclass AND conname = %s""",
                (table, name),
            ).fetchone()
            is not None
        )

    def _add_constraint_if_missing(
        self,
        connection: psycopg.Connection[dict[str, object]],
        table: str,
        name: str,
        definition: str,
    ) -> None:
        if self._constraint_exists(connection, table, name):
            return
        connection.execute(
            sql.SQL("ALTER TABLE {} ADD CONSTRAINT {} {}").format(
                sql.Identifier(table), sql.Identifier(name), sql.SQL(definition)
            )
        )

    @staticmethod
    def _backfill_artifact_digests(
        connection: psycopg.Connection[dict[str, object]],
    ) -> None:
        for table, id_column in (
            ("evaluation_runs", "run_id"),
            ("comparisons", "comparison_id"),
        ):
            rows = connection.execute(
                sql.SQL("SELECT {}, payload FROM {} WHERE payload_sha256 IS NULL").format(
                    sql.Identifier(id_column), sql.Identifier(table)
                )
            ).fetchall()
            for row in rows:
                connection.execute(
                    sql.SQL("UPDATE {} SET payload_sha256 = %s WHERE {} = %s").format(
                        sql.Identifier(table), sql.Identifier(id_column)
                    ),
                    (artifact_digest(row["payload"]), row[id_column]),
                )

    @contextmanager
    def _connect(self) -> Iterator[psycopg.Connection[dict[str, object]]]:
        if self._pool is not None:
            with self._pool.connection() as connection:
                self._set_tenant_context(connection)
                yield connection
            return
        with psycopg.connect(self.database_url, row_factory=dict_row) as connection:
            self._set_search_path(connection)
            self._set_tenant_context(connection)
            yield connection

    def _configure_pool_connection(self, connection: psycopg.Connection[dict[str, object]]) -> None:
        self._set_search_path(connection)
        connection.commit()

    def _migration_lock_key(self) -> int:
        digest = hashlib.sha256(f"aecontrol-schema:{self.schema}".encode()).digest()
        return int.from_bytes(digest[:8], byteorder="big", signed=True)

    def _set_search_path(self, connection: psycopg.Connection[object]) -> None:
        connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(self.schema)))

    @staticmethod
    def _set_tenant_context(connection: psycopg.Connection[object]) -> None:
        connection.execute(
            "SELECT set_config('aecontrol.tenant_id', %s, true)",
            (current_tenant_id(),),
        )
