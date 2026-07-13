from __future__ import annotations

from collections.abc import Iterable

from aecontrol.models import GateOutcome, JobStatus, OperationalSnapshot, WorkerRecord


def render_prometheus(snapshot: OperationalSnapshot, workers: Iterable[WorkerRecord] = ()) -> str:
    lines = [
        "# HELP aecontrol_runs_total Persisted evaluation runs.",
        "# TYPE aecontrol_runs_total gauge",
        f"aecontrol_runs_total {snapshot.runs_total}",
        "# HELP aecontrol_comparisons_total Persisted run comparisons.",
        "# TYPE aecontrol_comparisons_total gauge",
        f"aecontrol_comparisons_total {snapshot.comparisons_total}",
        "# HELP aecontrol_jobs Evaluation jobs by lifecycle state.",
        "# TYPE aecontrol_jobs gauge",
    ]
    lines.extend(
        f'aecontrol_jobs{{status="{status.value}"}} {snapshot.job_counts.get(status.value, 0)}'
        for status in JobStatus
    )
    lines.extend(
        [
            "# HELP aecontrol_gate_decisions Persisted gate decisions by outcome.",
            "# TYPE aecontrol_gate_decisions gauge",
        ]
    )
    lines.extend(
        f'aecontrol_gate_decisions{{outcome="{outcome.value}"}} '
        f"{snapshot.gate_counts.get(outcome.value, 0)}"
        for outcome in GateOutcome
    )
    lines.extend(
        [
            f"aecontrol_workers_registered {snapshot.workers_registered}",
            f"aecontrol_workers_active {snapshot.workers_active}",
            f"aecontrol_expired_leases {snapshot.expired_leases}",
            f"aecontrol_oldest_queued_seconds {snapshot.oldest_queued_seconds:.6f}",
            f"aecontrol_average_completed_job_seconds {snapshot.average_completed_job_seconds:.6f}",
        ]
    )
    lines.extend(
        [
            "# HELP aecontrol_gpu_memory_total_bytes GPU framebuffer memory capacity.",
            "# TYPE aecontrol_gpu_memory_total_bytes gauge",
            "# HELP aecontrol_gpu_memory_used_bytes GPU framebuffer memory in use.",
            "# TYPE aecontrol_gpu_memory_used_bytes gauge",
            "# HELP aecontrol_gpu_memory_available_bytes GPU framebuffer memory currently available.",
            "# TYPE aecontrol_gpu_memory_available_bytes gauge",
            "# HELP aecontrol_gpu_utilization_ratio GPU utilization from zero to one.",
            "# TYPE aecontrol_gpu_utilization_ratio gauge",
            "# HELP aecontrol_gpu_temperature_celsius GPU temperature in degrees Celsius.",
            "# TYPE aecontrol_gpu_temperature_celsius gauge",
            "# HELP aecontrol_gpu_power_draw_watts GPU board power draw in watts.",
            "# TYPE aecontrol_gpu_power_draw_watts gauge",
            "# HELP aecontrol_gpu_telemetry_timestamp_seconds Unix time of the worker telemetry sample.",
            "# TYPE aecontrol_gpu_telemetry_timestamp_seconds gauge",
        ]
    )
    gpu_metrics = (
        (worker.worker_id, worker.last_seen_at, gpu)
        for worker in workers
        for gpu in worker.capabilities.gpus
    )
    for worker_id, sampled_at, gpu in gpu_metrics:
        labels = (
            f'worker="{_escape_label(worker_id)}",gpu="{gpu.index}",'
            f'uuid="{_escape_label(gpu.uuid)}",name="{_escape_label(gpu.name)}"'
        )
        lines.append(
            f"aecontrol_gpu_telemetry_timestamp_seconds{{{labels}}} {sampled_at.timestamp():.6f}"
        )
        lines.append(
            f"aecontrol_gpu_memory_total_bytes{{{labels}}} {gpu.memory_total_mb * 1024**2}"
        )
        if gpu.memory_used_mb is not None:
            lines.append(
                f"aecontrol_gpu_memory_used_bytes{{{labels}}} {gpu.memory_used_mb * 1024**2}"
            )
            available_mb = max(0, gpu.memory_total_mb - gpu.memory_used_mb)
            lines.append(
                f"aecontrol_gpu_memory_available_bytes{{{labels}}} {available_mb * 1024**2}"
            )
        if gpu.utilization_percent is not None:
            lines.append(
                f"aecontrol_gpu_utilization_ratio{{{labels}}} {gpu.utilization_percent / 100:.6f}"
            )
        if gpu.temperature_celsius is not None:
            lines.append(
                f"aecontrol_gpu_temperature_celsius{{{labels}}} {gpu.temperature_celsius:.6f}"
            )
        if gpu.power_draw_watts is not None:
            lines.append(f"aecontrol_gpu_power_draw_watts{{{labels}}} {gpu.power_draw_watts:.6f}")
    return "\n".join(lines) + "\n"


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
