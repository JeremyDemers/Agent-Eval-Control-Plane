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
    load_constrained = (
        job.minimum_gpu_memory_available_mb > 0 or job.maximum_gpu_utilization_percent is not None
    )
    if (
        job.minimum_gpu_memory_mb == 0
        and job.minimum_cuda_compute_capability is None
        and not load_constrained
        and job.required_mig_profile is None
    ):
        return []
    if not gpus:
        return ["no GPU telemetry is available"]
    if any(_gpu_matches(job, gpu) for gpu in gpus):
        return []

    reasons: list[str] = []
    maximum_memory = max(gpu.memory_total_mb for gpu in gpus)
    if maximum_memory < job.minimum_gpu_memory_mb:
        reasons.append(
            f"GPU memory requires >= {job.minimum_gpu_memory_mb} MiB, maximum is {maximum_memory} MiB"
        )

    compute_values: list[float] = []
    for gpu in gpus:
        try:
            compute_values.append(float(gpu.compute_capability))
        except ValueError:
            continue
    if job.minimum_cuda_compute_capability is not None:
        if not compute_values:
            reasons.append("GPU compute capability telemetry is unavailable")
        elif max(compute_values) < job.minimum_cuda_compute_capability:
            reasons.append(
                "CUDA compute capability requires >= "
                f"{job.minimum_cuda_compute_capability:g}, maximum is {max(compute_values):g}"
            )

    available_values = [
        max(0, gpu.memory_total_mb - gpu.memory_used_mb)
        for gpu in gpus
        if gpu.memory_used_mb is not None
    ]
    if job.minimum_gpu_memory_available_mb > 0:
        if not available_values:
            reasons.append("GPU free-memory telemetry is unavailable")
        elif max(available_values) < job.minimum_gpu_memory_available_mb:
            reasons.append(
                "GPU free memory requires >= "
                f"{job.minimum_gpu_memory_available_mb} MiB, maximum is {max(available_values)} MiB"
            )

    utilization_values = [
        gpu.utilization_percent for gpu in gpus if gpu.utilization_percent is not None
    ]
    if job.maximum_gpu_utilization_percent is not None:
        if not utilization_values:
            reasons.append("GPU utilization telemetry is unavailable")
        elif min(utilization_values) > job.maximum_gpu_utilization_percent:
            reasons.append(
                "GPU utilization requires <= "
                f"{job.maximum_gpu_utilization_percent:g}%, minimum is {min(utilization_values):g}%"
            )
    if job.required_mig_profile is not None:
        mig_profiles = sorted({gpu.mig_profile for gpu in gpus if gpu.mig_profile is not None})
        if not mig_profiles:
            reasons.append("MIG profile telemetry is unavailable")
        elif job.required_mig_profile not in mig_profiles:
            reasons.append(
                f"MIG profile requires {job.required_mig_profile!r}, "
                f"available: {', '.join(mig_profiles)}"
            )
    if not reasons:
        reasons.append(
            "no single GPU satisfies all capacity, compute, and load requirements"
            if load_constrained
            else "no single GPU satisfies all memory and compute requirements"
        )
    return reasons


def _gpu_matches(job: EvaluationJob, gpu: GpuDevice) -> bool:
    if job.required_mig_profile is not None and gpu.mig_profile != job.required_mig_profile:
        return False
    if gpu.memory_total_mb < job.minimum_gpu_memory_mb:
        return False
    if job.minimum_cuda_compute_capability is not None:
        try:
            if float(gpu.compute_capability) < job.minimum_cuda_compute_capability:
                return False
        except ValueError:
            return False
    if job.minimum_gpu_memory_available_mb > 0:
        if gpu.memory_used_mb is None:
            return False
        if max(0, gpu.memory_total_mb - gpu.memory_used_mb) < job.minimum_gpu_memory_available_mb:
            return False
    return not (
        job.maximum_gpu_utilization_percent is not None
        and (
            gpu.utilization_percent is None
            or gpu.utilization_percent > job.maximum_gpu_utilization_percent
        )
    )
