from __future__ import annotations

import os
import re
from contextvars import ContextVar, Token

DEFAULT_TENANT_ID = "default"
TENANT_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,63}$"
_tenant_id_pattern = re.compile(TENANT_ID_PATTERN)
_current_tenant_id: ContextVar[str | None] = ContextVar("aecontrol_tenant_id", default=None)


def validate_tenant_id(tenant_id: str) -> str:
    if not _tenant_id_pattern.fullmatch(tenant_id):
        raise ValueError(
            "tenant ID must start with a lowercase letter or digit and contain only "
            "lowercase letters, digits, dots, underscores, or hyphens (maximum 64 characters)"
        )
    return tenant_id


def default_tenant_id() -> str:
    return validate_tenant_id(os.getenv("AECONTROL_TENANT_ID", DEFAULT_TENANT_ID))


def current_tenant_id() -> str:
    tenant_id = _current_tenant_id.get()
    return tenant_id if tenant_id is not None else default_tenant_id()


def bind_tenant(tenant_id: str) -> Token[str | None]:
    return _current_tenant_id.set(validate_tenant_id(tenant_id))


def reset_tenant(token: Token[str | None]) -> None:
    _current_tenant_id.reset(token)
