from aecontrol.models import OperationalSnapshot
from aecontrol.observability import render_prometheus


def test_prometheus_rendering_includes_zero_value_dimensions() -> None:
    payload = render_prometheus(
        OperationalSnapshot(
            runs_total=3,
            comparisons_total=2,
            job_counts={"completed": 1},
            gate_counts={"BLOCK": 1},
            workers_registered=2,
            workers_active=1,
            expired_leases=0,
            oldest_queued_seconds=0,
            average_completed_job_seconds=1.25,
        )
    )

    assert "aecontrol_runs_total 3" in payload
    assert 'aecontrol_jobs{status="queued"} 0' in payload
    assert 'aecontrol_jobs{status="completed"} 1' in payload
    assert 'aecontrol_gate_decisions{outcome="BLOCK"} 1' in payload
    assert "aecontrol_average_completed_job_seconds 1.250000" in payload
