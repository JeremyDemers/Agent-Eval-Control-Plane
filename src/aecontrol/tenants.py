from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aecontrol.tenancy import TENANT_ID_PATTERN

TenantStatus = Literal["active", "suspended"]
TenantScope = Literal["read", "write", "admin"]


class TenantConflictError(RuntimeError):
    pass


class TenantSuspendedError(RuntimeError):
    pass


class LastTenantAdminError(RuntimeError):
    pass


class TenantQuotaExceededError(RuntimeError):
    def __init__(self, quota: str, limit: int, observed: int) -> None:
        self.quota = quota
        self.limit = limit
        self.observed = observed
        super().__init__(f"tenant quota exceeded: {quota} limit={limit} observed={observed}")


class TenantQuotaLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_queued_jobs: int | None = Field(default=None, ge=0, le=100_000)
    max_jobs_per_hour: int | None = Field(default=None, ge=0, le=1_000_000)
    max_running_jobs: int | None = Field(default=None, ge=0, le=100_000)
    max_running_cuda_jobs: int | None = Field(default=None, ge=0, le=100_000)

    @model_validator(mode="after")
    def cuda_limit_cannot_exceed_total(self) -> TenantQuotaLimits:
        if (
            self.max_running_jobs is not None
            and self.max_running_cuda_jobs is not None
            and self.max_running_cuda_jobs > self.max_running_jobs
        ):
            raise ValueError("max_running_cuda_jobs cannot exceed max_running_jobs")
        return self


class TenantQuotaRecord(TenantQuotaLimits):
    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    updated_at: datetime
    updated_by: str


class TenantQuotaUsage(BaseModel):
    queued_jobs: int = Field(ge=0)
    active_running_jobs: int = Field(ge=0)
    active_running_cuda_jobs: int = Field(ge=0)
    jobs_submitted_last_hour: int = Field(ge=0)
    measured_at: datetime
    submission_window_started_at: datetime


class TenantQuotaStatus(BaseModel):
    quota: TenantQuotaRecord
    usage: TenantQuotaUsage


class TenantRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    display_name: str = Field(min_length=1, max_length=200)
    status: TenantStatus
    created_at: datetime
    created_by: str
    updated_at: datetime
    updated_by: str


class TenantAPIKeyRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    key_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    scopes: set[TenantScope] = Field(min_length=1)
    created_at: datetime
    created_by: str
    revoked_at: datetime | None = None
    revoked_by: str | None = None


class IssuedTenantAPIKey(BaseModel):
    tenant: TenantRecord
    key: TenantAPIKeyRecord
    secret: str = Field(min_length=32)


class ResolvedTenantAPIKey(BaseModel):
    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    key_id: str
    scopes: set[TenantScope]
