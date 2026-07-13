from aecontrol.models import (
    GpuDevice,
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
                )
            ],
        ),
        registered_at=utc_now(),
        last_seen_at=utc_now(),
    )
    payload = render_prometheus(snapshot, [worker])

    assert "aecontrol_runs_total 3" in payload
    assert "aecontrol_guardrail_evidence_total 4" in payload
    assert "aecontrol_guardrail_interventions_total 1" in payload
    assert 'aecontrol_jobs{status="queued"} 0' in payload
    assert 'aecontrol_jobs{status="completed"} 1' in payload
    assert 'aecontrol_gate_decisions{outcome="BLOCK"} 1' in payload
    assert "aecontrol_average_completed_job_seconds 1.250000" in payload
    assert 'worker="worker-\\"one\\""' in payload
    assert "aecontrol_gpu_memory_used_bytes" in payload
    assert "4194304000" in payload
    assert "aecontrol_gpu_memory_available_bytes" in payload
    assert "12582912000" in payload
    assert "aecontrol_gpu_utilization_ratio" in payload
    assert "0.250000" in payload
    assert "aecontrol_gpu_temperature_celsius" in payload
    assert "aecontrol_gpu_power_draw_watts" in payload
    assert "aecontrol_gpu_telemetry_timestamp_seconds" in payload
