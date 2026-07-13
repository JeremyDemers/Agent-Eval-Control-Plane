from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aecontrol.demand import forecast_gpu_demand
from aecontrol.models import GpuDurationEstimate

NOW = datetime(2026, 7, 13, 18, 37, tzinfo=UTC)


def _history(weeks: int, arrivals_per_slot: int = 2) -> list[tuple[datetime, int]]:
    target_hour = NOW.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    return [
        (target_hour - timedelta(weeks=week), arrivals_per_slot) for week in range(1, weeks + 1)
    ]


def test_forecast_uses_hour_of_week_rates_and_current_queue_demand() -> None:
    estimate = GpuDurationEstimate(
        mig_profile=None,
        sample_count=20,
        average_seconds=1800,
        p90_seconds=2400,
    )
    history = _history(8)
    history.extend((NOW - timedelta(days=day, hours=1), 1) for day in range(1, 21))

    forecast = forecast_gpu_demand(
        history,
        history_start=NOW - timedelta(days=56),
        observed_at=NOW,
        current_queued_cuda_jobs=2,
        current_running_cuda_jobs=1,
        active_cuda_workers=1,
        duration_estimate=estimate,
    )

    first = forecast.hours[0]
    assert first.hour_start == datetime(2026, 7, 13, 19, tzinfo=UTC)
    assert first.historical_occurrences == 8
    assert first.historical_arrivals == 16
    assert first.predicted_arrivals == 2
    assert forecast.historical_cuda_jobs == 36
    assert forecast.observed_history_hours == 1343
    assert forecast.predicted_cuda_arrivals == pytest.approx(2.375)
    assert forecast.projected_gpu_seconds == pytest.approx(9675)
    assert forecast.available_gpu_seconds == 86400
    assert forecast.projected_capacity_ratio == pytest.approx(9675 / 86400)
    assert forecast.confidence == "high"
    assert forecast.saturation == "within_capacity"


@pytest.mark.parametrize(
    ("duration_seconds", "workers", "expected"),
    [(35000, 1, "at_risk"), (44000, 1, "over_capacity"), (1000, 0, "unavailable")],
)
def test_forecast_classifies_projected_saturation(
    duration_seconds: float, workers: int, expected: str
) -> None:
    forecast = forecast_gpu_demand(
        _history(8),
        history_start=NOW - timedelta(days=56),
        observed_at=NOW,
        current_queued_cuda_jobs=0,
        current_running_cuda_jobs=0,
        active_cuda_workers=workers,
        duration_estimate=GpuDurationEstimate(
            mig_profile=None,
            sample_count=20,
            average_seconds=duration_seconds,
            p90_seconds=duration_seconds,
        ),
    )

    assert forecast.saturation == expected


def test_sparse_or_missing_evidence_never_claims_high_confidence() -> None:
    sparse = forecast_gpu_demand(
        _history(1),
        history_start=NOW - timedelta(days=7),
        observed_at=NOW,
        current_queued_cuda_jobs=1,
        current_running_cuda_jobs=0,
        active_cuda_workers=1,
        duration_estimate=GpuDurationEstimate(
            mig_profile=None, sample_count=1, average_seconds=60, p90_seconds=60
        ),
    )
    unavailable = forecast_gpu_demand(
        [],
        history_start=NOW - timedelta(days=7),
        observed_at=NOW,
        current_queued_cuda_jobs=1,
        current_running_cuda_jobs=0,
        active_cuda_workers=1,
        duration_estimate=None,
    )

    assert sparse.confidence == "low"
    assert unavailable.confidence == "unavailable"
    assert unavailable.projected_gpu_seconds is None
    assert unavailable.projected_capacity_ratio is None
    assert unavailable.saturation == "unavailable"


def test_forecast_rejects_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        forecast_gpu_demand(
            [],
            history_start=NOW.replace(tzinfo=None),
            observed_at=NOW,
            current_queued_cuda_jobs=0,
            current_running_cuda_jobs=0,
            active_cuda_workers=0,
            duration_estimate=None,
        )
    with pytest.raises(ValueError, match="cannot start after"):
        forecast_gpu_demand(
            [],
            history_start=NOW + timedelta(hours=1),
            observed_at=NOW,
            current_queued_cuda_jobs=0,
            current_running_cuda_jobs=0,
            active_cuda_workers=0,
            duration_estimate=None,
        )
    with pytest.raises(ValueError, match="counts cannot be negative"):
        forecast_gpu_demand(
            [(NOW - timedelta(hours=2), -1)],
            history_start=NOW - timedelta(days=1),
            observed_at=NOW,
            current_queued_cuda_jobs=0,
            current_running_cuda_jobs=0,
            active_cuda_workers=0,
            duration_estimate=None,
        )
