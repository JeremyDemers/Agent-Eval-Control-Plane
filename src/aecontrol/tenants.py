from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from aecontrol.tenancy import TENANT_ID_PATTERN

TenantStatus = Literal["active", "suspended"]
TenantScope = Literal["read", "write", "admin"]


class TenantConflictError(RuntimeError):
    pass


class TenantSuspendedError(RuntimeError):
    pass


class LastTenantAdminError(RuntimeError):
    pass


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
