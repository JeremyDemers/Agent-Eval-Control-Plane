from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Literal

from aecontrol.models import GpuDemandForecast, GpuDemandHour, GpuDurationEstimate

DEFAULT_LOOKBACK_DAYS = 56
DEFAULT_HORIZON_HOURS = 24
HIGH_CONFIDENCE_HISTORY_HOURS = 28 * 24
HIGH_CONFIDENCE_JOBS = 20
HIGH_CONFIDENCE_DURATIONS = 10


def forecast_gpu_demand(
    hourly_arrivals: Sequence[tuple[datetime, int]],
    *,
    history_start: datetime,
    observed_at: datetime,
    current_queued_cuda_jobs: int,
    current_running_cuda_jobs: int,
    active_cuda_workers: int,
    duration_estimate: GpuDurationEstimate | None,
    lookback_days: int = DEFAULT_LOOKBACK_DAYS,
    horizon_hours: int = DEFAULT_HORIZON_HOURS,
) -> GpuDemandForecast:
    if history_start.tzinfo is None or observed_at.tzinfo is None:
        raise ValueError("GPU demand timestamps must be timezone-aware")
    if history_start > observed_at:
        raise ValueError("GPU demand history cannot start after the observation time")
    if lookback_days <= 0 or horizon_hours <= 0:
        raise ValueError("GPU demand lookback and horizon must be positive")
    if current_queued_cuda_jobs < 0 or current_running_cuda_jobs < 0 or active_cuda_workers < 0:
        raise ValueError("GPU demand queue and worker counts cannot be negative")

    observed = observed_at.astimezone(UTC)
    earliest = max(history_start.astimezone(UTC), observed - timedelta(days=lookback_days))
    first_hour = _ceil_hour(earliest)
    observed_hour = _floor_hour(observed)

    occurrence_counts: dict[tuple[int, int], int] = defaultdict(int)
    cursor = first_hour
    while cursor < observed_hour:
        occurrence_counts[(cursor.weekday(), cursor.hour)] += 1
        cursor += timedelta(hours=1)

    arrivals_by_slot: dict[tuple[int, int], int] = defaultdict(int)
    historical_cuda_jobs = 0
    for hour_start, count in hourly_arrivals:
        if hour_start.tzinfo is None:
            raise ValueError("GPU arrival buckets must be timezone-aware")
        if count < 0:
            raise ValueError("GPU arrival counts cannot be negative")
        hour = _floor_hour(hour_start.astimezone(UTC))
        if first_hour <= hour < observed_hour:
            arrivals_by_slot[(hour.weekday(), hour.hour)] += count
            historical_cuda_jobs += count

    hours: list[GpuDemandHour] = []
    for offset in range(1, horizon_hours + 1):
        hour_start = observed_hour + timedelta(hours=offset)
        key = (hour_start.weekday(), hour_start.hour)
        occurrences = occurrence_counts[key]
        arrivals = arrivals_by_slot[key]
        predicted = arrivals / occurrences if occurrences else 0.0
        hours.append(
            GpuDemandHour(
                hour_start=hour_start,
                historical_occurrences=occurrences,
                historical_arrivals=arrivals,
                predicted_arrivals=predicted,
            )
        )

    observed_history_hours = max(0, int((observed_hour - first_hour).total_seconds() // 3600))
    predicted_cuda_arrivals = sum(item.predicted_arrivals for item in hours)
    average_duration = duration_estimate.average_seconds if duration_estimate is not None else None
    projected_gpu_seconds = (
        (current_queued_cuda_jobs + current_running_cuda_jobs + predicted_cuda_arrivals)
        * average_duration
        if average_duration is not None
        else None
    )
    available_gpu_seconds = float(active_cuda_workers * horizon_hours * 3600)
    capacity_ratio = (
        projected_gpu_seconds / available_gpu_seconds
        if projected_gpu_seconds is not None and available_gpu_seconds > 0
        else None
    )
    confidence: Literal["unavailable", "low", "high"] = "unavailable"
    if historical_cuda_jobs > 0 and duration_estimate is not None and observed_history_hours > 0:
        confidence = (
            "high"
            if observed_history_hours >= HIGH_CONFIDENCE_HISTORY_HOURS
            and historical_cuda_jobs >= HIGH_CONFIDENCE_JOBS
            and duration_estimate.sample_count >= HIGH_CONFIDENCE_DURATIONS
            else "low"
        )
    saturation: Literal["unavailable", "within_capacity", "at_risk", "over_capacity"]
    if capacity_ratio is None or confidence == "unavailable":
        saturation = "unavailable"
    elif capacity_ratio > 1:
        saturation = "over_capacity"
    elif capacity_ratio >= 0.8:
        saturation = "at_risk"
    else:
        saturation = "within_capacity"

    return GpuDemandForecast(
        observed_at=observed,
        history_start=earliest,
        lookback_days=lookback_days,
        horizon_hours=horizon_hours,
        historical_cuda_jobs=historical_cuda_jobs,
        observed_history_hours=observed_history_hours,
        current_queued_cuda_jobs=current_queued_cuda_jobs,
        current_running_cuda_jobs=current_running_cuda_jobs,
        predicted_cuda_arrivals=predicted_cuda_arrivals,
        average_cuda_duration_seconds=average_duration,
        projected_gpu_seconds=projected_gpu_seconds,
        available_gpu_seconds=available_gpu_seconds,
        projected_capacity_ratio=capacity_ratio,
        active_cuda_workers=active_cuda_workers,
        confidence=confidence,
        saturation=saturation,
        hours=hours,
    )


def _floor_hour(value: datetime) -> datetime:
    return value.replace(minute=0, second=0, microsecond=0)


def _ceil_hour(value: datetime) -> datetime:
    floor = _floor_hour(value)
    return floor if value == floor else floor + timedelta(hours=1)
