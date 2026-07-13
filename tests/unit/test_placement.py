from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aecontrol.models import (
    Accelerator,
    EvaluationJob,
    GpuDevice,
    JobStatus,
    WorkerCapabilities,
    WorkerRecord,
)
from aecontrol.placement import diagnose_placement

NOW = datetime(2026, 7, 12, 20, 0, tzinfo=UTC)


def _worker(
    worker_id: str,
    *,
    seen_seconds_ago: int = 0,
    accelerators: list[Accelerator] | None = None,
    labels: dict[str, str] | None = None,
    gpus: list[GpuDevice] | None = None,
) -> WorkerRecord:
    return WorkerRecord(
        worker_id=worker_id,
        capabilities=WorkerCapabilities(
            hostname=f"{worker_id}-host",
            operating_system="linux",
            architecture="x86_64",
            cpu_count=8,
            accelerators=accelerators or [Accelerator.CPU],
            labels=labels or {},
            gpus=gpus or [],
        ),
        registered_at=NOW - timedelta(hours=1),
        last_seen_at=NOW - timedelta(seconds=seen_seconds_ago),
    )


def test_diagnostic_explains_stale_accelerator_and_label_blockers() -> None:
    job = EvaluationJob(
        suite_path="suite.yaml",
        agent_version="openai/model",
        required_accelerator=Accelerator.CUDA,
        required_labels={"runtime": "openai-compatible"},
    )
    diagnostic = diagnose_placement(
        job,
        [_worker("cpu", seen_seconds_ago=121, labels={"runtime": "ollama"})],
        now=NOW,
    )

    assert diagnostic.schedulable is False
    assert diagnostic.active_workers == 0
    assert diagnostic.blockers == ["no workers have an active heartbeat"]
    assert diagnostic.workers[0].reasons == [
        "worker heartbeat is stale",
        "missing cuda accelerator",
        "label runtime requires 'openai-compatible', found 'ollama'",
    ]


def test_diagnostic_requires_one_complete_gpu_profile() -> None:
    job = EvaluationJob(
        suite_path="suite.yaml",
        agent_version="baseline",
        required_accelerator=Accelerator.CUDA,
        minimum_gpu_memory_mb=12000,
        minimum_cuda_compute_capability=8.9,
    )
    split = _worker(
        "split",
        accelerators=[Accelerator.CPU, Accelerator.CUDA],
        gpus=[
            GpuDevice(name="fast-small", memory_total_mb=8000, compute_capability="9.0"),
            GpuDevice(name="large-old", memory_total_mb=24000, compute_capability="8.0"),
        ],
    )
    qualified = _worker(
        "qualified",
        accelerators=[Accelerator.CPU, Accelerator.CUDA],
        gpus=[GpuDevice(name="ada", memory_total_mb=16000, compute_capability="8.9")],
    )

    diagnostic = diagnose_placement(job, [split, qualified], now=NOW)

    assert diagnostic.schedulable is True
    assert diagnostic.matching_workers == 1
    assert diagnostic.workers[0].reasons == [
        "no single GPU satisfies all memory and compute requirements"
    ]
    assert diagnostic.workers[1].eligible is True


def test_diagnostic_summarizes_empty_terminal_jobs_and_validates_window() -> None:
    job = EvaluationJob(
        suite_path="suite.yaml", agent_version="baseline", status=JobStatus.COMPLETED
    )
    diagnostic = diagnose_placement(job, [], now=NOW)
    assert diagnostic.blockers == [
        "job status is completed, not queued",
        "no workers are registered",
    ]
    with pytest.raises(ValueError, match="window must be positive"):
        diagnose_placement(job, [], now=NOW, active_within_seconds=0)


def test_diagnostic_explains_live_gpu_load_and_requires_one_device() -> None:
    job = EvaluationJob(
        suite_path="suite.yaml",
        agent_version="baseline",
        required_accelerator=Accelerator.CUDA,
        minimum_gpu_memory_available_mb=8000,
        maximum_gpu_utilization_percent=30,
    )
    split = _worker(
        "split-load",
        accelerators=[Accelerator.CPU, Accelerator.CUDA],
        gpus=[
            GpuDevice(
                name="free-busy",
                memory_total_mb=24000,
                memory_used_mb=1000,
                utilization_percent=90,
                compute_capability="9.0",
            ),
            GpuDevice(
                name="idle-full",
                memory_total_mb=24000,
                memory_used_mb=20000,
                utilization_percent=5,
                compute_capability="9.0",
            ),
        ],
    )
    missing = _worker(
        "missing-load",
        accelerators=[Accelerator.CPU, Accelerator.CUDA],
        gpus=[GpuDevice(name="unknown", memory_total_mb=24000, compute_capability="9.0")],
    )
    qualified = _worker(
        "qualified-load",
        accelerators=[Accelerator.CPU, Accelerator.CUDA],
        gpus=[
            GpuDevice(
                name="available",
                memory_total_mb=24000,
                memory_used_mb=4000,
                utilization_percent=20,
                compute_capability="9.0",
            )
        ],
    )

    diagnostic = diagnose_placement(job, [split, missing, qualified], now=NOW)

    assert diagnostic.matching_workers == 1
    assert diagnostic.workers[0].reasons == [
        "no single GPU satisfies all capacity, compute, and load requirements"
    ]
    assert diagnostic.workers[1].reasons == [
        "GPU free-memory telemetry is unavailable",
        "GPU utilization telemetry is unavailable",
    ]
    assert diagnostic.workers[2].eligible is True
