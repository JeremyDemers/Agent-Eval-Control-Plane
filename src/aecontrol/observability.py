from __future__ import annotations

from aecontrol.models import GateOutcome, JobStatus, OperationalSnapshot


def render_prometheus(snapshot: OperationalSnapshot) -> str:
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
    return "\n".join(lines) + "\n"
