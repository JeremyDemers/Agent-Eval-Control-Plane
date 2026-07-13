from __future__ import annotations

import pytest

from aecontrol.tenancy import (
    DEFAULT_TENANT_ID,
    bind_tenant,
    current_tenant_id,
    default_tenant_id,
    reset_tenant,
    validate_tenant_id,
)


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
