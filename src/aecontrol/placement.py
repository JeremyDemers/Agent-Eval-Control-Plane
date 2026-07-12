from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aecontrol.models import (
    EvaluationJob,
    GpuDevice,
    JobPlacementDiagnostic,
    JobStatus,
    WorkerPlacementDiagnostic,
    WorkerRecord,
)

DEFAULT_WORKER_ACTIVE_SECONDS = 120


def diagnose_placement(
    job: EvaluationJob,
    workers: list[WorkerRecord],
    *,
    now: datetime | None = None,
    active_within_seconds: int = DEFAULT_WORKER_ACTIVE_SECONDS,
) -> JobPlacementDiagnostic:
    if active_within_seconds <= 0:
        raise ValueError("active worker window must be positive")
    observed_at = now or datetime.now(UTC)
    active_after = observed_at - timedelta(seconds=active_within_seconds)
    worker_diagnostics = [
        _diagnose_worker(job, worker, worker.last_seen_at >= active_after) for worker in workers
    ]
    active_workers = sum(item.active for item in worker_diagnostics)
    matching_workers = sum(item.eligible for item in worker_diagnostics)
    blockers: list[str] = []
    if job.status != JobStatus.QUEUED:
        blockers.append(f"job status is {job.status.value}, not queued")
    if not workers:
        blockers.append("no workers are registered")
    elif active_workers == 0:
        blockers.append("no workers have an active heartbeat")
    elif matching_workers == 0:
        blockers.append("no active worker satisfies the placement requirements")
    return JobPlacementDiagnostic(
        job_id=job.job_id,
        job_status=job.status,
        observed_at=observed_at,
        active_worker_window_seconds=active_within_seconds,
        schedulable=job.status == JobStatus.QUEUED and matching_workers > 0,
        active_workers=active_workers,
        matching_workers=matching_workers,
        blockers=blockers,
        workers=worker_diagnostics,
    )


def _diagnose_worker(
    job: EvaluationJob, worker: WorkerRecord, active: bool
) -> WorkerPlacementDiagnostic:
    reasons: list[str] = []
    capabilities = worker.capabilities
    if not active:
        reasons.append("worker heartbeat is stale")
    if job.required_accelerator not in capabilities.accelerators:
        reasons.append(f"missing {job.required_accelerator.value} accelerator")
    for key, required in job.required_labels.items():
        actual = capabilities.labels.get(key)
        if actual != required:
            reasons.append(f"label {key} requires {required!r}, found {actual!r}")
    reasons.extend(_gpu_reasons(job, capabilities.gpus))
    return WorkerPlacementDiagnostic(
        worker_id=worker.worker_id,
        active=active,
        eligible=not reasons,
        last_seen_at=worker.last_seen_at,
        reasons=reasons,
    )


def _gpu_reasons(job: EvaluationJob, gpus: list[GpuDevice]) -> list[str]:
    if job.minimum_gpu_memory_mb == 0 and job.minimum_cuda_compute_capability is None:
        return []
    profiles: list[tuple[int, float]] = []
    for gpu in gpus:
        memory = gpu.memory_total_mb
        try:
            compute = float(gpu.compute_capability)
        except ValueError:
            continue
        profiles.append((memory, compute))
    if not profiles:
        return ["no GPU has readable memory and compute capability"]
    matching = [
        profile
        for profile in profiles
        if profile[0] >= job.minimum_gpu_memory_mb
        and (
            job.minimum_cuda_compute_capability is None
            or profile[1] >= job.minimum_cuda_compute_capability
        )
    ]
    if matching:
        return []
    reasons: list[str] = []
    maximum_memory = max(profile[0] for profile in profiles)
    maximum_compute = max(profile[1] for profile in profiles)
    if maximum_memory < job.minimum_gpu_memory_mb:
        reasons.append(
            f"GPU memory requires >= {job.minimum_gpu_memory_mb} MiB, maximum is {maximum_memory} MiB"
        )
    if (
        job.minimum_cuda_compute_capability is not None
        and maximum_compute < job.minimum_cuda_compute_capability
    ):
        reasons.append(
            "CUDA compute capability requires >= "
            f"{job.minimum_cuda_compute_capability:g}, maximum is {maximum_compute:g}"
        )
    if not reasons:
        reasons.append("no single GPU satisfies all memory and compute requirements")
    return reasons
