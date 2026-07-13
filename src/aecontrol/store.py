from __future__ import annotations

import re
from threading import Lock
from typing import Literal, cast
from uuid import UUID

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from aecontrol.guardrails import (
    GuardrailEvidence,
    StoredGuardrailEvidence,
    StoredGuardrailEvidenceSummary,
)
from aecontrol.integrity import ArtifactIntegrityError, artifact_digest
from aecontrol.models import (
    Accelerator,
    ArtifactIntegrityItem,
    ArtifactIntegrityReport,
    EvaluationJob,
    EvaluationRun,
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
from aecontrol.placement import diagnose_placement

SCHEMA_VERSION = 6


class ArtifactStore:
    """PostgreSQL storage for complete evaluation and comparison artifacts."""

    def __init__(self, database_url: str, schema: str = "public") -> None:
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", schema):
            msg = f"invalid PostgreSQL schema name: {schema}"
            raise ValueError(msg)
        self.database_url = database_url
        self.schema = schema
        self._initialized = False
        self._initialize_lock = Lock()

    def initialize(self) -> None:
        if self._initialized:
            return
        with self._initialize_lock:
            if self._initialized:
                return
            self._initialize_schema()
            self._initialized = True

    def _initialize_schema(self) -> None:
        with psycopg.connect(self.database_url, row_factory=dict_row) as connection:
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
                """
                CREATE TABLE IF NOT EXISTS workers (
                    worker_id TEXT PRIMARY KEY,
                    capabilities JSONB NOT NULL,
                    registered_at TIMESTAMPTZ NOT NULL,
                    last_seen_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            self._backfill_artifact_digests(connection)
            connection.execute(
                "ALTER TABLE evaluation_runs ALTER COLUMN payload_sha256 SET NOT NULL"
            )
            connection.execute("ALTER TABLE comparisons ALTER COLUMN payload_sha256 SET NOT NULL")
            row = connection.execute("SELECT version FROM schema_metadata LIMIT 1").fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO schema_metadata(version) VALUES (%s)", (SCHEMA_VERSION,)
                )
            elif int(row["version"]) in {1, 2, 3, 4, 5}:
                connection.execute("UPDATE schema_metadata SET version = %s", (SCHEMA_VERSION,))
            elif int(row["version"]) != SCHEMA_VERSION:
                msg = f"unsupported database schema version: {row['version']}"
                raise RuntimeError(msg)

    def save_run(self, run: EvaluationRun) -> None:
        self.initialize()
        case_count = len(run.case_results)
        hidden_passes = sum(result.hidden_success for result in run.case_results)
        hidden_pass_rate = hidden_passes / case_count if case_count else 0.0
        payload = run.model_dump(mode="json")
        digest = artifact_digest(payload)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO evaluation_runs (
                    run_id, suite_name, dataset_name, dataset_version, agent_version,
                    started_at, completed_at, case_count, hidden_pass_rate, payload, payload_sha256
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                    payload_sha256 = excluded.payload_sha256
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
                ),
            )

    def get_run(self, run_id: UUID) -> EvaluationRun:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload, payload_sha256 FROM evaluation_runs WHERE run_id = %s", (run_id,)
            ).fetchone()
        if row is None:
            raise KeyError(str(run_id))
        self._verify_artifact("run", run_id, row["payload_sha256"], row["payload"])
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
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO comparisons (
                    comparison_id, baseline_run_id, candidate_run_id, created_at,
                    outcome, paired_cases, aggregate_pass_rate_delta, payload, payload_sha256
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                ),
            )
        return artifact

    def get_comparison(self, comparison_id: UUID) -> StoredComparison:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload, payload_sha256 FROM comparisons WHERE comparison_id = %s",
                (comparison_id,),
            ).fetchone()
        if row is None:
            raise KeyError(str(comparison_id))
        self._verify_artifact("comparison", comparison_id, row["payload_sha256"], row["payload"])
        return StoredComparison.model_validate(row["payload"])

    def save_guardrail_evidence(self, evidence: GuardrailEvidence) -> StoredGuardrailEvidence:
        self.initialize()
        artifact = StoredGuardrailEvidence(evidence=evidence)
        payload = artifact.model_dump(mode="json")
        digest = artifact_digest(payload)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO guardrail_evidence (
                    evidence_id, created_at, config_id, model, passed_through,
                    payload, payload_sha256
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    artifact.evidence_id,
                    artifact.created_at,
                    evidence.config_id,
                    evidence.model,
                    evidence.passed_through,
                    Jsonb(payload),
                    digest,
                ),
            )
        return artifact

    def get_guardrail_evidence(self, evidence_id: UUID) -> StoredGuardrailEvidence:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload, payload_sha256 FROM guardrail_evidence WHERE evidence_id = %s",
                (evidence_id,),
            ).fetchone()
        if row is None:
            raise KeyError(str(evidence_id))
        self._verify_artifact(
            "guardrail_evidence", evidence_id, row["payload_sha256"], row["payload"]
        )
        return StoredGuardrailEvidence.model_validate(row["payload"])

    def list_guardrail_evidence(self, limit: int = 100) -> list[StoredGuardrailEvidenceSummary]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT evidence_id, created_at, config_id, model, passed_through
                FROM guardrail_evidence ORDER BY created_at DESC LIMIT %s
                """,
                (limit,),
            ).fetchall()
        return [StoredGuardrailEvidenceSummary.model_validate(row) for row in rows]

    def verify_artifacts(self) -> ArtifactIntegrityReport:
        self.initialize()
        failures: list[ArtifactIntegrityItem] = []
        checked = 0
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
                    sql.SQL("SELECT {}, payload, payload_sha256 FROM {}").format(
                        sql.Identifier(id_column), sql.Identifier(table)
                    )
                ).fetchall()
                checked += len(rows)
                for row in rows:
                    actual = artifact_digest(row["payload"])
                    expected = str(row["payload_sha256"])
                    if actual != expected:
                        failures.append(
                            ArtifactIntegrityItem(
                                artifact_type=artifact_type,
                                artifact_id=cast(UUID, row[id_column]),
                                valid=False,
                                expected_sha256=expected,
                                actual_sha256=actual,
                            )
                        )
        return ArtifactIntegrityReport(
            checked=checked, valid=checked - len(failures), failures=failures
        )

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
                    traceparent, request_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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

    def lease_job(
        self,
        worker_id: str,
        lease_seconds: int = 900,
        capabilities: WorkerCapabilities | None = None,
    ) -> EvaluationJob | None:
        self.initialize()
        accelerators = [Accelerator.CPU.value]
        labels: dict[str, str] = {}
        gpu_profiles: list[dict[str, int | float | None]] = []
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
                        )
                        OR EXISTS (
                          SELECT 1
                          FROM jsonb_to_recordset(%s::jsonb)
                            AS gpu(
                              memory_total_mb INTEGER,
                              memory_used_mb INTEGER,
                              compute_capability DOUBLE PRECISION,
                              utilization_percent DOUBLE PRECISION
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
                ON CONFLICT(worker_id) DO UPDATE SET
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
                    updated_at = now(), lease_owner = NULL, lease_expires_at = NULL, error = %s
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

    @staticmethod
    def _verify_artifact(
        artifact_type: str,
        artifact_id: UUID,
        expected_value: object,
        payload: object,
    ) -> None:
        expected = str(expected_value)
        actual = artifact_digest(payload)
        if actual != expected:
            raise ArtifactIntegrityError(artifact_type, artifact_id, expected, actual)

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

    def _connect(self) -> psycopg.Connection[dict[str, object]]:
        connection = psycopg.connect(self.database_url, row_factory=dict_row)
        self._set_search_path(connection)
        return connection

    def _set_search_path(self, connection: psycopg.Connection[object]) -> None:
        connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(self.schema)))
