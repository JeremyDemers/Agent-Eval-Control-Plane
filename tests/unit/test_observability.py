from datetime import UTC, datetime

from aecontrol.database import DatabasePoolSnapshot
from aecontrol.guardrails import GuardrailEfficacyMetrics, GuardrailEfficacyReport
from aecontrol.models import (
    GpuCapacityForecast,
    GpuDemandForecast,
    GpuDevice,
    GpuDurationEstimate,
    OperationalSnapshot,
    WorkerCapabilities,
    WorkerRecord,
    utc_now,
)
from aecontrol.observability import render_prometheus


def test_prometheus_rendering_includes_zero_value_dimensions() -> None:
    snapshot = OperationalSnapshot(
        runs_total=3,
        comparisons_total=2,
        guardrail_evidence_total=4,
        guardrail_interventions_total=1,
        job_counts={"completed": 1},
        gate_counts={"BLOCK": 1},
        workers_registered=2,
        workers_active=1,
        expired_leases=0,
        oldest_queued_seconds=0,
        average_completed_job_seconds=1.25,
    )
    worker = WorkerRecord(
        worker_id='worker-"one"',
        capabilities=WorkerCapabilities(
            hostname="gpu-host",
            operating_system="linux",
            architecture="x86_64",
            cpu_count=8,
            accelerators=["cpu", "cuda"],
            gpus=[
                GpuDevice(
                    index=0,
                    uuid="GPU-test",
                    name="RTX Test",
                    memory_total_mb=16000,
                    memory_used_mb=4000,
                    utilization_percent=25,
                    temperature_celsius=55,
                    power_draw_watts=80,
                    compute_capability="8.9",
                    mig_profile="3g.40gb",
                    telemetry_source="dcgm-exporter",
                )
            ],
        ),
        registered_at=utc_now(),
        last_seen_at=utc_now(),
    )
    capacity = GpuCapacityForecast(
        observed_at=utc_now(),
        active_worker_window_seconds=120,
        active_cuda_workers=1,
        active_gpus=1,
        memory_telemetry_gpus=1,
        utilization_telemetry_gpus=1,
        total_gpu_memory_mb=16000,
        available_gpu_memory_mb=12000,
        average_gpu_utilization_percent=25,
        queued_cuda_jobs=4,
        first_wave_jobs=1,
        deferred_jobs=2,
        blocked_jobs=1,
        minimum_clearance_waves=3,
        estimated_clearance_seconds=270,
        estimate_confidence="high",
        duration_estimates=[
            GpuDurationEstimate(
                mig_profile="3g.40gb",
                sample_count=12,
                average_seconds=70,
                p90_seconds=90,
            )
        ],
        jobs=[],
    )
    efficacy = GuardrailEfficacyReport(
        window_start=datetime(2026, 7, 1, tzinfo=UTC),
        window_end=datetime(2026, 8, 1, tzinfo=UTC),
        total_checks=5,
        labeled_checks=4,
        versions=[
            GuardrailEfficacyMetrics(
                config_id="content_safety",
                config_version="1.0",
                sample_count=5,
                labeled_count=4,
                pass_through_count=3,
                intervention_count=2,
                true_positives=1,
                false_positives=1,
                true_negatives=2,
                false_negatives=0,
                label_coverage=0.8,
                intervention_rate=0.4,
                accuracy=0.75,
                precision=0.5,
                recall=1,
                false_positive_rate=1 / 3,
            )
        ],
    )
    pool = DatabasePoolSnapshot(minimum=1, maximum=8, size=3, available=2, waiting=1)
    demand = GpuDemandForecast(
        observed_at=utc_now(),
        history_start=datetime(2026, 5, 18, tzinfo=UTC),
        lookback_days=56,
        horizon_hours=24,
        historical_cuda_jobs=24,
        observed_history_hours=1344,
        current_queued_cuda_jobs=2,
        current_running_cuda_jobs=1,
        predicted_cuda_arrivals=3.5,
        average_cuda_duration_seconds=600,
        projected_gpu_seconds=3900,
        available_gpu_seconds=86400,
        projected_capacity_ratio=0.045139,
        active_cuda_workers=1,
        confidence="high",
        saturation="within_capacity",
        hours=[],
    )
    payload = render_prometheus(snapshot, [worker], capacity, efficacy, pool, demand)

    assert "aecontrol_runs_total 3" in payload
    assert "aecontrol_guardrail_evidence_total 4" in payload
    assert "aecontrol_guardrail_interventions_total 1" in payload
    assert 'aecontrol_jobs{status="queued"} 0' in payload
    assert 'aecontrol_jobs{status="completed"} 1' in payload
    assert 'aecontrol_gate_decisions{outcome="BLOCK"} 1' in payload
    assert "aecontrol_average_completed_job_seconds 1.250000" in payload
    assert 'worker="worker-\\"one\\""' in payload
    assert 'partition="mig",mig_profile="3g.40gb",telemetry_source="dcgm-exporter"' in payload
    assert "aecontrol_gpu_memory_used_bytes" in payload
    assert "4194304000" in payload
    assert "aecontrol_gpu_memory_available_bytes" in payload
    assert "12582912000" in payload
    assert "aecontrol_gpu_utilization_ratio" in payload
    assert "0.250000" in payload
    assert "aecontrol_gpu_temperature_celsius" in payload
    assert "aecontrol_gpu_power_draw_watts" in payload
    assert "aecontrol_gpu_telemetry_timestamp_seconds" in payload
    assert 'aecontrol_gpu_queue_jobs{state="first_wave"} 1' in payload
    assert 'aecontrol_gpu_queue_jobs{state="deferred"} 2' in payload
    assert 'aecontrol_gpu_queue_jobs{state="blocked"} 1' in payload
    assert "aecontrol_gpu_queue_clearance_waves 3" in payload
    assert "aecontrol_gpu_active_workers 1" in payload
    assert "aecontrol_gpu_queue_estimated_clearance_seconds 270.000000" in payload
    assert 'aecontrol_gpu_queue_estimate_confidence{level="high"} 1' in payload
    assert 'aecontrol_gpu_queue_estimate_confidence{level="low"} 0' in payload
    assert 'aecontrol_gpu_job_duration_samples{mig_profile="3g.40gb"} 12' in payload
    assert 'mig_profile="3g.40gb",quantile="p90"} 90.000000' in payload
    assert "aecontrol_guardrail_labeled_checks 4" in payload
    assert "aecontrol_guardrail_label_coverage 0.800000" in payload
    assert "aecontrol_guardrail_policy_accuracy 0.750000" in payload
    assert "aecontrol_guardrail_false_positive_rate 0.333333" in payload
    assert 'aecontrol_database_pool_connections{state="size"} 3' in payload
    assert 'aecontrol_database_pool_connections{state="available"} 2' in payload
    assert 'aecontrol_database_pool_limit{bound="maximum"} 8' in payload
    assert "aecontrol_database_pool_waiting_requests 1" in payload
    assert "aecontrol_gpu_demand_predicted_arrivals 3.500000" in payload
    assert "aecontrol_gpu_demand_capacity_ratio 0.045139" in payload
    assert 'aecontrol_gpu_demand_confidence{level="high"} 1' in payload
    assert 'aecontrol_gpu_demand_confidence{level="low"} 0' in payload
