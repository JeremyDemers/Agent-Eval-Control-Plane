from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

JsonValue = Any
MIG_PROFILE_PATTERN = r"^(?:[1-9][0-9]*c\.)?[1-9][0-9]*g\.[1-9][0-9]*gb(?:\+me)?$"


def normalize_mig_profile(value: str) -> str:
    profile = value.strip().lower()
    if re.fullmatch(MIG_PROFILE_PATTERN, profile) is None:
        raise ValueError(f"invalid NVIDIA MIG profile: {value!r}")
    return profile


def utc_now() -> datetime:
    return datetime.now(UTC)


class ExecutionStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


class GateOutcome(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"
    INCONCLUSIVE = "INCONCLUSIVE"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Accelerator(StrEnum):
    CPU = "cpu"
    CUDA = "cuda"


class Message(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str


class AgentVersion(BaseModel):
    name: str
    version: str
    description: str = ""


class DatasetCase(BaseModel):
    case_id: str
    title: str
    slice: str
    bug_kind: str
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    expected_tools: list[str] = Field(default_factory=list)
    forbidden_tools: list[str] = Field(default_factory=list)
    expected_modified_files: list[str] = Field(default_factory=list)
    forbidden_modified_files: list[str] = Field(default_factory=list)

    @field_validator("case_id", "slice", "bug_kind")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value.strip():
            msg = "value must not be empty"
            raise ValueError(msg)
        return value


class DatasetSlice(BaseModel):
    name: str
    case_ids: list[str]


class Dataset(BaseModel):
    name: str
    version: str
    cases: list[DatasetCase]
    slices: list[DatasetSlice]


class EvaluationSuite(BaseModel):
    name: str
    dataset_path: str
    evaluators: list[str]
    concurrency: int = Field(default=4, ge=1, le=32)


class ToolCall(BaseModel):
    call_id: UUID = Field(default_factory=uuid4)
    name: str
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=utc_now)


class ToolResult(BaseModel):
    call_id: UUID
    name: str
    ok: bool
    output: str
    completed_at: datetime = Field(default_factory=utc_now)


class TrajectoryStep(BaseModel):
    step_id: UUID = Field(default_factory=uuid4)
    kind: Literal[
        "message",
        "tool_call",
        "tool_result",
        "graph_node",
        "graph_event",
        "error",
        "final",
    ]
    timestamp: datetime = Field(default_factory=utc_now)
    data: dict[str, JsonValue]


class AgentTrajectory(BaseModel):
    trajectory_id: UUID = Field(default_factory=uuid4)
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    steps: list[TrajectoryStep] = Field(default_factory=list)


class ExecutionError(BaseModel):
    error_type: str
    message: str


class AgentInput(BaseModel):
    case_id: str
    messages: list[Message] = Field(default_factory=list)
    variables: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class AgentOutput(BaseModel):
    final_response: Message | None = None
    trajectory: AgentTrajectory
    patch: str
    modified_files: list[str]
    public_test_output: str
    hidden_test_output: str
    duration_seconds: float
    status: ExecutionStatus
    error: ExecutionError | None = None
    runtime_metadata: dict[str, JsonValue] = Field(default_factory=dict)


class EvaluationResult(BaseModel):
    name: str
    passed: bool
    score: float = Field(ge=0.0, le=1.0)
    explanation: str
    metric_value: float | None = None


class CaseResult(BaseModel):
    case: DatasetCase
    agent_version: str
    status: ExecutionStatus
    started_at: datetime
    completed_at: datetime
    output: AgentOutput
    evaluator_results: list[EvaluationResult]

    @property
    def hidden_success(self) -> bool:
        return any(
            result.name == "hidden_test_success" and result.passed
            for result in self.evaluator_results
        )


class EvaluationRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: UUID = Field(default_factory=uuid4)
    suite_name: str
    dataset_name: str
    dataset_version: str
    agent_version: str
    started_at: datetime
    completed_at: datetime
    case_results: list[CaseResult]


class CaseComparison(BaseModel):
    case_id: str
    slice: str
    baseline_passed: bool
    candidate_passed: bool
    classification: Literal["improved", "regressed", "unchanged_pass", "unchanged_fail"]
    metric_deltas: dict[str, float] = Field(default_factory=dict)
    explanation: str


class SliceComparison(BaseModel):
    slice: str
    paired_cases: int
    baseline_pass_rate: float
    candidate_pass_rate: float
    pass_rate_delta: float


class RunComparison(BaseModel):
    baseline_run_id: UUID
    candidate_run_id: UUID
    paired_cases: int
    missing_pairs: list[str]
    aggregate_pass_rate_delta: float
    metric_deltas: dict[str, float] = Field(default_factory=dict)
    confidence_interval: tuple[float, float] | None
    limited_evidence: bool
    improved_cases: list[str]
    regressed_cases: list[str]
    unchanged_passes: int
    unchanged_failures: int
    slice_comparisons: list[SliceComparison]
    case_comparisons: list[CaseComparison]


class MetricRule(BaseModel):
    required: bool = False
    maximum_absolute_drop: float | None = None
    maximum_absolute_increase: float | None = None
    severity: Literal["blocking", "warning"] = "blocking"


class QualityGatePolicy(BaseModel):
    schema_version: str
    policy: dict[str, str]
    defaults: dict[str, int] = Field(default_factory=dict)
    metrics: dict[str, MetricRule] = Field(default_factory=dict)
    slices: dict[str, dict[str, MetricRule]] = Field(default_factory=dict)


class GateFinding(BaseModel):
    scope: str
    metric: str
    outcome: GateOutcome
    observed_delta: float | None
    threshold: float | None
    message: str


class QualityGateDecision(BaseModel):
    outcome: GateOutcome
    findings: list[GateFinding]
    regressed_cases: list[str]


class StoredRunSummary(BaseModel):
    run_id: UUID
    suite_name: str
    dataset_name: str
    dataset_version: str
    agent_version: str
    started_at: datetime
    completed_at: datetime
    case_count: int
    hidden_pass_rate: float


class StoredComparison(BaseModel):
    comparison_id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=utc_now)
    comparison: RunComparison
    decision: QualityGateDecision


class StoredComparisonSummary(BaseModel):
    comparison_id: UUID
    baseline_run_id: UUID
    candidate_run_id: UUID
    created_at: datetime
    outcome: GateOutcome
    paired_cases: int
    aggregate_pass_rate_delta: float


class ArtifactIntegrityItem(BaseModel):
    artifact_type: Literal["run", "comparison", "guardrail_evidence"]
    artifact_id: UUID
    valid: bool
    expected_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    actual_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    failure_kind: Literal["digest", "signature", "missing_signing_key"] = "digest"
    signature_algorithm: str | None = None
    signing_key_id: str | None = None


class ArtifactIntegrityReport(BaseModel):
    checked: int = Field(ge=0)
    valid: int = Field(ge=0)
    signed: int = Field(default=0, ge=0)
    unsigned: int = Field(default=0, ge=0)
    signature_algorithms: dict[str, int] = Field(default_factory=dict)
    failures: list[ArtifactIntegrityItem]


class EvaluationJob(BaseModel):
    job_id: UUID = Field(default_factory=uuid4)
    suite_path: str
    agent_version: str
    status: JobStatus = JobStatus.QUEUED
    priority: int = Field(default=0, ge=-100, le=100)
    attempts: int = Field(default=0, ge=0)
    max_attempts: int = Field(default=3, ge=1, le=10)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    run_id: UUID | None = None
    error: str | None = None
    required_accelerator: Accelerator = Accelerator.CPU
    required_labels: dict[str, str] = Field(default_factory=dict)
    minimum_gpu_memory_mb: int = Field(default=0, ge=0)
    minimum_cuda_compute_capability: float | None = Field(default=None, ge=1)
    minimum_gpu_memory_available_mb: int = Field(default=0, ge=0)
    maximum_gpu_utilization_percent: float | None = Field(default=None, ge=0, le=100)
    required_mig_profile: str | None = Field(default=None, pattern=MIG_PROFILE_PATTERN)
    traceparent: str | None = Field(
        default=None, pattern=r"^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$"
    )
    request_id: str | None = None

    @field_validator("required_mig_profile", mode="before")
    @classmethod
    def normalize_required_mig_profile(cls, value: str | None) -> str | None:
        return normalize_mig_profile(value) if value is not None else None

    @model_validator(mode="after")
    def gpu_constraints_require_cuda(self) -> EvaluationJob:
        if (
            self.minimum_gpu_memory_mb > 0
            or self.minimum_cuda_compute_capability is not None
            or self.minimum_gpu_memory_available_mb > 0
            or self.maximum_gpu_utilization_percent is not None
            or self.required_mig_profile is not None
        ) and self.required_accelerator != Accelerator.CUDA:
            raise ValueError("GPU resource constraints require the cuda accelerator")
        return self


class GpuDevice(BaseModel):
    index: int = Field(default=0, ge=0)
    uuid: str = ""
    name: str
    memory_total_mb: int = Field(ge=0)
    compute_capability: str
    memory_used_mb: int | None = Field(default=None, ge=0)
    utilization_percent: float | None = Field(default=None, ge=0, le=100)
    temperature_celsius: float | None = None
    power_draw_watts: float | None = Field(default=None, ge=0)
    mig_profile: str | None = Field(default=None, pattern=MIG_PROFILE_PATTERN)
    telemetry_source: Literal["nvidia-smi", "dcgm-exporter", "unavailable"] = "unavailable"

    @field_validator("mig_profile", mode="before")
    @classmethod
    def normalize_device_mig_profile(cls, value: str | None) -> str | None:
        return normalize_mig_profile(value) if value is not None else None


class WorkerCapabilities(BaseModel):
    hostname: str
    operating_system: str
    architecture: str
    cpu_count: int = Field(ge=1)
    accelerators: list[Accelerator]
    gpus: list[GpuDevice] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)


class WorkerRecord(BaseModel):
    worker_id: str
    capabilities: WorkerCapabilities
    registered_at: datetime
    last_seen_at: datetime


class WorkerPlacementDiagnostic(BaseModel):
    worker_id: str
    active: bool
    eligible: bool
    last_seen_at: datetime
    reasons: list[str]


class JobPlacementDiagnostic(BaseModel):
    job_id: UUID
    job_status: JobStatus
    observed_at: datetime
    active_worker_window_seconds: int = Field(gt=0)
    schedulable: bool
    active_workers: int = Field(ge=0)
    matching_workers: int = Field(ge=0)
    blockers: list[str]
    workers: list[WorkerPlacementDiagnostic]


class GpuQueueJobForecast(BaseModel):
    job_id: UUID
    agent_version: str
    priority: int
    state: Literal["first_wave", "deferred", "blocked"]
    matching_workers: int = Field(ge=0)
    assigned_worker_id: str | None = None
    blockers: list[str] = Field(default_factory=list)


class GpuDurationEstimate(BaseModel):
    mig_profile: str | None = Field(default=None, pattern=MIG_PROFILE_PATTERN)
    sample_count: int = Field(ge=1)
    average_seconds: float = Field(gt=0)
    p90_seconds: float = Field(gt=0)

    @field_validator("mig_profile", mode="before")
    @classmethod
    def normalize_estimate_mig_profile(cls, value: str | None) -> str | None:
        return normalize_mig_profile(value) if value is not None else None


class GpuCapacityForecast(BaseModel):
    observed_at: datetime
    active_worker_window_seconds: int = Field(gt=0)
    active_cuda_workers: int = Field(ge=0)
    active_gpus: int = Field(ge=0)
    memory_telemetry_gpus: int = Field(ge=0)
    utilization_telemetry_gpus: int = Field(ge=0)
    total_gpu_memory_mb: int = Field(ge=0)
    available_gpu_memory_mb: int = Field(ge=0)
    average_gpu_utilization_percent: float | None = Field(default=None, ge=0, le=100)
    queued_cuda_jobs: int = Field(ge=0)
    first_wave_jobs: int = Field(ge=0)
    deferred_jobs: int = Field(ge=0)
    blocked_jobs: int = Field(ge=0)
    minimum_clearance_waves: int = Field(ge=0)
    estimated_clearance_seconds: float | None = Field(default=None, ge=0)
    estimate_confidence: Literal["unavailable", "low", "high"] = "unavailable"
    duration_estimates: list[GpuDurationEstimate] = Field(default_factory=list)
    jobs: list[GpuQueueJobForecast]


class GpuDemandHour(BaseModel):
    hour_start: datetime
    historical_occurrences: int = Field(ge=0)
    historical_arrivals: int = Field(ge=0)
    predicted_arrivals: float = Field(ge=0)


class GpuDemandForecast(BaseModel):
    observed_at: datetime
    history_start: datetime
    lookback_days: int = Field(gt=0)
    horizon_hours: int = Field(gt=0)
    historical_cuda_jobs: int = Field(ge=0)
    observed_history_hours: int = Field(ge=0)
    current_queued_cuda_jobs: int = Field(ge=0)
    current_running_cuda_jobs: int = Field(ge=0)
    predicted_cuda_arrivals: float = Field(ge=0)
    average_cuda_duration_seconds: float | None = Field(default=None, gt=0)
    projected_gpu_seconds: float | None = Field(default=None, ge=0)
    available_gpu_seconds: float = Field(ge=0)
    projected_capacity_ratio: float | None = Field(default=None, ge=0)
    active_cuda_workers: int = Field(ge=0)
    confidence: Literal["unavailable", "low", "high"]
    saturation: Literal["unavailable", "within_capacity", "at_risk", "over_capacity"]
    hours: list[GpuDemandHour]


class OperationalSnapshot(BaseModel):
    runs_total: int = Field(ge=0)
    comparisons_total: int = Field(ge=0)
    guardrail_evidence_total: int = Field(ge=0)
    guardrail_interventions_total: int = Field(ge=0)
    job_counts: dict[str, int]
    gate_counts: dict[str, int]
    workers_registered: int = Field(ge=0)
    workers_active: int = Field(ge=0)
    expired_leases: int = Field(ge=0)
    oldest_queued_seconds: float = Field(ge=0)
    average_completed_job_seconds: float = Field(ge=0)


class ValidationIssue(BaseModel):
    location: str
    message: str


class ValidationReport(BaseModel):
    valid: bool
    issues: list[ValidationIssue] = Field(default_factory=list)
