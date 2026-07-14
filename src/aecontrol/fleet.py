from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from aecontrol.tenancy import TENANT_ID_PATTERN
from aecontrol.tenants import TenantQuotaLimits

FleetTenantStatus = Literal["active", "suspended", "unregistered"]


class FleetResourceSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    queued_cpu_jobs: int = Field(ge=0)
    queued_cuda_jobs: int = Field(ge=0)
    active_running_cpu_jobs: int = Field(ge=0)
    active_running_cuda_jobs: int = Field(ge=0)
    jobs_submitted_last_hour: int = Field(ge=0)
    workers_observed: int = Field(ge=0)
    active_cpu_workers: int = Field(ge=0)
    active_cuda_workers: int = Field(ge=0)
    active_gpu_devices: int = Field(ge=0)
    oldest_queued_seconds: float = Field(ge=0)


class FleetQuotaSaturation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    queued_jobs: bool
    jobs_per_hour: bool
    running_jobs: bool
    running_cuda_jobs: bool


class TenantFleetSummary(FleetResourceSnapshot):
    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    display_name: str | None = None
    status: FleetTenantStatus
    quota: TenantQuotaLimits
    saturation: FleetQuotaSaturation


class PlatformFleetReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observed_at: datetime
    active_worker_window_seconds: int = Field(gt=0)
    totals: FleetResourceSnapshot
    tenants: list[TenantFleetSummary]
