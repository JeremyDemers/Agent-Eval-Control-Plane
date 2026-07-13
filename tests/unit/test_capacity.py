from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aecontrol.capacity import _maximum_matching, forecast_gpu_capacity
from aecontrol.models import (
    Accelerator,
    EvaluationJob,
    GpuDevice,
    JobStatus,
    WorkerCapabilities,
    WorkerRecord,
)

NOW = datetime(2026, 7, 13, 18, 0, tzinfo=UTC)


def _worker(
    worker_id: str,
    memory_mb: int,
    used_mb: int,
    utilization: float,
    *,
    stale: bool = False,
) -> WorkerRecord:
    capabilities = WorkerCapabilities(
        hostname=worker_id,
        operating_system="linux",
        architecture="x86_64",
        cpu_count=16,
        accelerators=[Accelerator.CPU, Accelerator.CUDA],
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
    )
    return WorkerRecord(
        worker_id=worker_id,
        capabilities=capabilities,
        registered_at=NOW - timedelta(hours=1),
        last_seen_at=NOW - timedelta(minutes=5) if stale else NOW,
    )


def _job(
    priority: int, minimum_memory_mb: int, *, status: JobStatus = JobStatus.QUEUED
) -> EvaluationJob:
    return EvaluationJob(
        suite_path="suite.yaml",
        agent_version=f"nim/model-{priority}",
        status=status,
        priority=priority,
        required_accelerator=Accelerator.CUDA,
        minimum_gpu_memory_mb=minimum_memory_mb,
    )


def test_forecast_maximizes_priority_wave_and_finds_minimum_clearance() -> None:
    workers = [
        _worker("a100", 81920, 20000, 30),
        _worker("l4", 24576, 4096, 10),
        _worker("stale", 81920, 0, 0, stale=True),
    ]
    high_flexible = _job(10, 16000)
    constrained = _job(5, 40000)
    deferred = _job(0, 16000)
    blocked = _job(-1, 100000)
    completed = _job(100, 0, status=JobStatus.COMPLETED)

    forecast = forecast_gpu_capacity(
        [deferred, blocked, constrained, completed, high_flexible], workers, now=NOW
    )

    assert forecast.active_cuda_workers == 2
    assert forecast.active_gpus == 2
    assert forecast.memory_telemetry_gpus == 2
    assert forecast.utilization_telemetry_gpus == 2
    assert forecast.total_gpu_memory_mb == 106496
    assert forecast.available_gpu_memory_mb == 82400
    assert forecast.average_gpu_utilization_percent == 20
    assert forecast.queued_cuda_jobs == 4
    assert forecast.first_wave_jobs == 2
    assert forecast.deferred_jobs == 1
    assert forecast.blocked_jobs == 1
    assert forecast.minimum_clearance_waves == 2

    by_id = {item.job_id: item for item in forecast.jobs}
    assert by_id[high_flexible.job_id].state == "first_wave"
    assert by_id[high_flexible.job_id].assigned_worker_id == "l4"
    assert by_id[constrained.job_id].state == "first_wave"
    assert by_id[constrained.job_id].assigned_worker_id == "a100"
    assert by_id[deferred.job_id].state == "deferred"
    assert by_id[blocked.job_id].state == "blocked"
    assert by_id[blocked.job_id].matching_workers == 0
    assert by_id[blocked.job_id].blockers == [
        "no active worker satisfies the placement requirements"
    ]


def test_forecast_handles_no_compatible_gpu_capacity() -> None:
    cpu_worker = WorkerRecord(
        worker_id="cpu",
        capabilities=WorkerCapabilities(
            hostname="cpu",
            operating_system="linux",
            architecture="x86_64",
            cpu_count=4,
            accelerators=[Accelerator.CPU],
        ),
        registered_at=NOW,
        last_seen_at=NOW,
    )

    forecast = forecast_gpu_capacity([_job(0, 1)], [cpu_worker], now=NOW)

    assert forecast.active_cuda_workers == 0
    assert forecast.first_wave_jobs == 0
    assert forecast.blocked_jobs == 1
    assert forecast.minimum_clearance_waves == 0


def test_forecast_rejects_invalid_active_window() -> None:
    with pytest.raises(ValueError, match="active worker window must be positive"):
        forecast_gpu_capacity([], [], active_within_seconds=0)


def test_matching_handles_long_augmenting_paths_without_recursion() -> None:
    job_ids = list(range(1101))
    eligible_slots = {job_id: [job_id, job_id + 1] for job_id in job_ids[:-1]}
    eligible_slots[job_ids[-1]] = [0]

    matching = _maximum_matching(job_ids, eligible_slots)

    assert len(matching) == len(job_ids)
    assert len(set(matching.values())) == len(job_ids)
