from __future__ import annotations

from collections.abc import Iterable

from aecontrol.database import DatabasePoolSnapshot
from aecontrol.guardrails import GuardrailEfficacyReport
from aecontrol.models import (
    GateOutcome,
    GpuCapacityForecast,
    JobStatus,
    OperationalSnapshot,
    WorkerRecord,
)


def render_prometheus(
    snapshot: OperationalSnapshot,
    workers: Iterable[WorkerRecord] = (),
    gpu_capacity: GpuCapacityForecast | None = None,
    guardrail_efficacy: GuardrailEfficacyReport | None = None,
    database_pool: DatabasePoolSnapshot | None = None,
) -> str:
    lines = [
        "# HELP aecontrol_runs_total Persisted evaluation runs.",
        "# TYPE aecontrol_runs_total gauge",
        f"aecontrol_runs_total {snapshot.runs_total}",
        "# HELP aecontrol_comparisons_total Persisted run comparisons.",
        "# TYPE aecontrol_comparisons_total gauge",
        f"aecontrol_comparisons_total {snapshot.comparisons_total}",
        "# HELP aecontrol_guardrail_evidence_total Persisted NeMo Guardrails checks.",
        "# TYPE aecontrol_guardrail_evidence_total gauge",
        f"aecontrol_guardrail_evidence_total {snapshot.guardrail_evidence_total}",
        "# HELP aecontrol_guardrail_interventions_total Guardrails checks that changed the submitted text.",
        "# TYPE aecontrol_guardrail_interventions_total gauge",
        f"aecontrol_guardrail_interventions_total {snapshot.guardrail_interventions_total}",
        "# HELP aecontrol_jobs Evaluation jobs by lifecycle state.",
        "# TYPE aecontrol_jobs gauge",
    ]
    lines.extend(
        f'aecontrol_jobs{{status="{status.value}"}} {snapshot.job_counts.get(status.value, 0)}'
        for status in JobStatus
    )
    if database_pool is not None:
        lines.extend(
            [
                "# HELP aecontrol_database_pool_connections Database connections by pool state.",
                "# TYPE aecontrol_database_pool_connections gauge",
                f'aecontrol_database_pool_connections{{state="size"}} {database_pool.size}',
                f'aecontrol_database_pool_connections{{state="available"}} {database_pool.available}',
                "# HELP aecontrol_database_pool_limit Configured database connection pool bounds.",
                "# TYPE aecontrol_database_pool_limit gauge",
                f'aecontrol_database_pool_limit{{bound="minimum"}} {database_pool.minimum}',
                f'aecontrol_database_pool_limit{{bound="maximum"}} {database_pool.maximum}',
                "# HELP aecontrol_database_pool_waiting_requests Requests waiting for a database connection.",
                "# TYPE aecontrol_database_pool_waiting_requests gauge",
                f"aecontrol_database_pool_waiting_requests {database_pool.waiting}",
            ]
        )
    if guardrail_efficacy is not None:
        correct = sum(
            item.true_positives + item.true_negatives for item in guardrail_efficacy.versions
        )
        false_positives = sum(item.false_positives for item in guardrail_efficacy.versions)
        true_negatives = sum(item.true_negatives for item in guardrail_efficacy.versions)
        lines.extend(
            [
                "# HELP aecontrol_guardrail_labeled_checks Guardrails checks carrying expected-action labels in the reporting window.",
                "# TYPE aecontrol_guardrail_labeled_checks gauge",
                f"aecontrol_guardrail_labeled_checks {guardrail_efficacy.labeled_checks}",
                "# HELP aecontrol_guardrail_label_coverage Ratio of checks carrying expected-action labels in the reporting window.",
                "# TYPE aecontrol_guardrail_label_coverage gauge",
                "aecontrol_guardrail_label_coverage "
                f"{_ratio(guardrail_efficacy.labeled_checks, guardrail_efficacy.total_checks):.6f}",
            ]
        )
        if guardrail_efficacy.labeled_checks:
            lines.extend(
                [
                    "# HELP aecontrol_guardrail_policy_accuracy Correct expected-action decisions among labeled checks.",
                    "# TYPE aecontrol_guardrail_policy_accuracy gauge",
                    "aecontrol_guardrail_policy_accuracy "
                    f"{_ratio(correct, guardrail_efficacy.labeled_checks):.6f}",
                ]
            )
        if false_positives + true_negatives:
            lines.extend(
                [
                    "# HELP aecontrol_guardrail_false_positive_rate Unexpected interventions among expected pass-through checks.",
                    "# TYPE aecontrol_guardrail_false_positive_rate gauge",
                    "aecontrol_guardrail_false_positive_rate "
                    f"{_ratio(false_positives, false_positives + true_negatives):.6f}",
                ]
            )
    if gpu_capacity is not None:
        lines.extend(
            [
                "# HELP aecontrol_gpu_queue_jobs CUDA jobs by forecast state.",
                "# TYPE aecontrol_gpu_queue_jobs gauge",
                f'aecontrol_gpu_queue_jobs{{state="first_wave"}} {gpu_capacity.first_wave_jobs}',
                f'aecontrol_gpu_queue_jobs{{state="deferred"}} {gpu_capacity.deferred_jobs}',
                f'aecontrol_gpu_queue_jobs{{state="blocked"}} {gpu_capacity.blocked_jobs}',
                "# HELP aecontrol_gpu_queue_clearance_waves Minimum scheduling waves for compatible queued CUDA jobs.",
                "# TYPE aecontrol_gpu_queue_clearance_waves gauge",
                f"aecontrol_gpu_queue_clearance_waves {gpu_capacity.minimum_clearance_waves}",
                "# HELP aecontrol_gpu_active_workers Active CUDA worker scheduling slots.",
                "# TYPE aecontrol_gpu_active_workers gauge",
                f"aecontrol_gpu_active_workers {gpu_capacity.active_cuda_workers}",
                "# HELP aecontrol_gpu_queue_estimated_clearance_seconds Historical p90 estimate for compatible CUDA queue clearance.",
                "# TYPE aecontrol_gpu_queue_estimated_clearance_seconds gauge",
                "# HELP aecontrol_gpu_queue_estimate_confidence Historical queue estimate confidence by fixed level.",
                "# TYPE aecontrol_gpu_queue_estimate_confidence gauge",
            ]
        )
        if gpu_capacity.estimated_clearance_seconds is not None:
            lines.append(
                "aecontrol_gpu_queue_estimated_clearance_seconds "
                f"{gpu_capacity.estimated_clearance_seconds:.6f}"
            )
        for level in ("unavailable", "low", "high"):
            value = int(gpu_capacity.estimate_confidence == level)
            lines.append(f'aecontrol_gpu_queue_estimate_confidence{{level="{level}"}} {value}')
        lines.extend(
            [
                "# HELP aecontrol_gpu_job_duration_seconds Historical completed CUDA attempt duration by request class.",
                "# TYPE aecontrol_gpu_job_duration_seconds gauge",
                "# HELP aecontrol_gpu_job_duration_samples Completed CUDA attempts in each duration estimate.",
                "# TYPE aecontrol_gpu_job_duration_samples gauge",
            ]
        )
        for estimate in gpu_capacity.duration_estimates:
            profile = _escape_label(estimate.mig_profile or "all")
            lines.append(
                f'aecontrol_gpu_job_duration_seconds{{mig_profile="{profile}",quantile="average"}} '
                f"{estimate.average_seconds:.6f}"
            )
            lines.append(
                f'aecontrol_gpu_job_duration_seconds{{mig_profile="{profile}",quantile="p90"}} '
                f"{estimate.p90_seconds:.6f}"
            )
            lines.append(
                f'aecontrol_gpu_job_duration_samples{{mig_profile="{profile}"}} '
                f"{estimate.sample_count}"
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
            f'uuid="{_escape_label(gpu.uuid)}",name="{_escape_label(gpu.name)}",'
            f'partition="{"mig" if gpu.mig_profile else "full"}",'
            f'mig_profile="{_escape_label(gpu.mig_profile or "")}"'
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


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0
