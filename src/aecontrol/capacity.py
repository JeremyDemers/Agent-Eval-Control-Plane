from __future__ import annotations

from collections import deque
from collections.abc import Hashable
from datetime import UTC, datetime, timedelta
from typing import Literal

from aecontrol.models import (
    Accelerator,
    EvaluationJob,
    GpuCapacityForecast,
    GpuDurationEstimate,
    GpuQueueJobForecast,
    JobStatus,
    WorkerRecord,
)
from aecontrol.placement import DEFAULT_WORKER_ACTIVE_SECONDS, diagnose_placement


def forecast_gpu_capacity(
    jobs: list[EvaluationJob],
    workers: list[WorkerRecord],
    *,
    now: datetime | None = None,
    active_within_seconds: int = DEFAULT_WORKER_ACTIVE_SECONDS,
    duration_estimates: list[GpuDurationEstimate] | None = None,
) -> GpuCapacityForecast:
    if active_within_seconds <= 0:
        raise ValueError("active worker window must be positive")
    observed_at = now or datetime.now(UTC)
    active_after = observed_at - timedelta(seconds=active_within_seconds)
    active_cuda_workers = sorted(
        (
            worker
            for worker in workers
            if worker.last_seen_at >= active_after
            and Accelerator.CUDA in worker.capabilities.accelerators
        ),
        key=lambda worker: worker.worker_id,
    )
    queued_jobs = sorted(
        (
            job
            for job in jobs
            if job.status == JobStatus.QUEUED and job.required_accelerator == Accelerator.CUDA
        ),
        key=lambda job: (-job.priority, job.created_at, str(job.job_id)),
    )

    diagnostics = {
        job.job_id: diagnose_placement(
            job,
            workers,
            now=observed_at,
            active_within_seconds=active_within_seconds,
        )
        for job in queued_jobs
    }
    eligible_workers = {
        job.job_id: [
            item.worker_id
            for item in diagnostics[job.job_id].workers
            if item.active and item.eligible
        ]
        for job in queued_jobs
    }
    compatible_jobs = [job for job in queued_jobs if eligible_workers[job.job_id]]
    first_wave = _maximum_matching([job.job_id for job in compatible_jobs], eligible_workers)
    minimum_clearance_waves = _minimum_clearance_waves(
        [job.job_id for job in compatible_jobs], eligible_workers
    )
    estimates = duration_estimates or []
    estimates_by_profile = {item.mig_profile: item for item in estimates}
    selected_estimates = [
        estimates_by_profile.get(job.required_mig_profile) for job in compatible_jobs
    ]
    has_complete_history = bool(selected_estimates) and all(
        item is not None for item in selected_estimates
    )
    estimated_clearance_seconds: float | None = None
    estimate_confidence: Literal["unavailable", "low", "high"] = "unavailable"
    if has_complete_history:
        complete_estimates = [item for item in selected_estimates if item is not None]
        estimated_clearance_seconds = (
            max(item.p90_seconds for item in complete_estimates) * minimum_clearance_waves
        )
        estimate_confidence = (
            "high" if min(item.sample_count for item in complete_estimates) >= 10 else "low"
        )

    job_forecasts: list[GpuQueueJobForecast] = []
    for job in queued_jobs:
        matching = eligible_workers[job.job_id]
        assigned_worker = first_wave.get(job.job_id)
        state: Literal["first_wave", "deferred", "blocked"]
        if not matching:
            state = "blocked"
        elif assigned_worker is None:
            state = "deferred"
        else:
            state = "first_wave"
        job_forecasts.append(
            GpuQueueJobForecast(
                job_id=job.job_id,
                agent_version=job.agent_version,
                priority=job.priority,
                state=state,
                matching_workers=len(matching),
                assigned_worker_id=assigned_worker,
                blockers=diagnostics[job.job_id].blockers if state == "blocked" else [],
            )
        )

    gpus = [gpu for worker in active_cuda_workers for gpu in worker.capabilities.gpus]
    utilization = [gpu.utilization_percent for gpu in gpus if gpu.utilization_percent is not None]
    return GpuCapacityForecast(
        observed_at=observed_at,
        active_worker_window_seconds=active_within_seconds,
        active_cuda_workers=len(active_cuda_workers),
        active_gpus=len(gpus),
        memory_telemetry_gpus=sum(gpu.memory_used_mb is not None for gpu in gpus),
        utilization_telemetry_gpus=len(utilization),
        total_gpu_memory_mb=sum(gpu.memory_total_mb for gpu in gpus),
        available_gpu_memory_mb=sum(
            max(0, gpu.memory_total_mb - gpu.memory_used_mb)
            for gpu in gpus
            if gpu.memory_used_mb is not None
        ),
        average_gpu_utilization_percent=(
            sum(utilization) / len(utilization) if utilization else None
        ),
        queued_cuda_jobs=len(queued_jobs),
        first_wave_jobs=len(first_wave),
        deferred_jobs=sum(item.state == "deferred" for item in job_forecasts),
        blocked_jobs=sum(item.state == "blocked" for item in job_forecasts),
        minimum_clearance_waves=minimum_clearance_waves,
        estimated_clearance_seconds=estimated_clearance_seconds,
        estimate_confidence=estimate_confidence,
        duration_estimates=estimates,
        jobs=job_forecasts,
    )


def _minimum_clearance_waves[JobId: Hashable](
    job_ids: list[JobId], eligible_workers: dict[JobId, list[str]]
) -> int:
    if not job_ids:
        return 0
    lower = 1
    upper = len(job_ids)
    while lower < upper:
        waves = (lower + upper) // 2
        worker_slots = {
            job_id: [
                (worker_id, wave) for worker_id in eligible_workers[job_id] for wave in range(waves)
            ]
            for job_id in job_ids
        }
        if len(_maximum_matching(job_ids, worker_slots)) == len(job_ids):
            upper = waves
        else:
            lower = waves + 1
    return lower


def _maximum_matching[JobId: Hashable, Slot: Hashable](
    job_ids: list[JobId], eligible_slots: dict[JobId, list[Slot]]
) -> dict[JobId, Slot]:
    slot_to_job: dict[Slot, JobId] = {}
    job_to_slot: dict[JobId, Slot] = {}

    for root_job in job_ids:
        queue = deque([root_job])
        visited_jobs = {root_job}
        visited_slots: set[Slot] = set()
        slot_parent: dict[Slot, JobId] = {}
        free_slot: Slot | None = None
        while queue and free_slot is None:
            job_id = queue.popleft()
            for slot in eligible_slots[job_id]:
                if slot in visited_slots:
                    continue
                visited_slots.add(slot)
                slot_parent[slot] = job_id
                incumbent = slot_to_job.get(slot)
                if incumbent is None:
                    free_slot = slot
                    break
                if incumbent not in visited_jobs:
                    visited_jobs.add(incumbent)
                    queue.append(incumbent)
        while free_slot is not None:
            job_id = slot_parent[free_slot]
            previous_slot = job_to_slot.get(job_id)
            slot_to_job[free_slot] = job_id
            job_to_slot[job_id] = free_slot
            free_slot = previous_slot
    return job_to_slot
