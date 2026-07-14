from __future__ import annotations

import pytest
from pydantic import ValidationError

from aecontrol.tenancy import (
    DEFAULT_TENANT_ID,
    bind_tenant,
    current_tenant_id,
    default_tenant_id,
    reset_tenant,
    validate_tenant_id,
)
from aecontrol.tenants import TenantQuotaExceededError, TenantQuotaLimits


def test_tenant_ids_are_bounded_slugs(monkeypatch: pytest.MonkeyPatch) -> None:
    assert validate_tenant_id("nvidia-platform_1.prod") == "nvidia-platform_1.prod"
    for tenant_id in ("", "Uppercase", "two/levels", "a" * 65):
        with pytest.raises(ValueError, match="tenant ID"):
            validate_tenant_id(tenant_id)

    monkeypatch.delenv("AECONTROL_TENANT_ID", raising=False)
    assert default_tenant_id() == DEFAULT_TENANT_ID
    monkeypatch.setenv("AECONTROL_TENANT_ID", "batch-evaluations")
    assert default_tenant_id() == "batch-evaluations"


def test_tenant_binding_is_context_local() -> None:
    original = current_tenant_id()
    token = bind_tenant("tenant-a")
    try:
        assert current_tenant_id() == "tenant-a"
    finally:
        reset_tenant(token)
    assert current_tenant_id() == original


def test_tenant_quota_limits_are_bounded_and_consistent() -> None:
    assert TenantQuotaLimits(max_running_jobs=0, max_running_cuda_jobs=0).max_running_jobs == 0
    with pytest.raises(ValidationError, match="cannot exceed"):
        TenantQuotaLimits(max_running_jobs=1, max_running_cuda_jobs=2)
    with pytest.raises(ValidationError):
        TenantQuotaLimits(max_queued_jobs=100_001)

    error = TenantQuotaExceededError("max_queued_jobs", 10, 11)
    assert (error.quota, error.limit, error.observed) == ("max_queued_jobs", 10, 11)
