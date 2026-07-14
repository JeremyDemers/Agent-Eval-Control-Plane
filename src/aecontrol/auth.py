from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
from collections.abc import Awaitable, Callable
from contextlib import suppress
from pathlib import Path
from typing import Annotated, Literal

import yaml
from fastapi import HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, model_validator

from aecontrol.federation import (
    FederatedTokenVerifier,
    FederationError,
    OIDCFederatedTokenVerifier,
)
from aecontrol.tenancy import (
    DEFAULT_TENANT_ID,
    TENANT_ID_PATTERN,
    bind_tenant,
    default_tenant_id,
)
from aecontrol.tenants import ResolvedTenantAPIKey

AuthScope = Literal["read", "write", "admin", "operator"]


class APIKey(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str = Field(min_length=1, max_length=64)
    tenant_id: str = Field(default=DEFAULT_TENANT_ID, pattern=TENANT_ID_PATTERN)
    secret_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    scopes: set[AuthScope] = Field(min_length=1)

    @model_validator(mode="after")
    def isolate_operator_scope(self) -> APIKey:
        if "operator" in self.scopes and self.scopes != {"operator"}:
            raise ValueError("operator API keys cannot include tenant scopes")
        return self


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    keys: list[APIKey] = Field(min_length=1)


class Principal(BaseModel):
    key_id: str
    tenant_id: str
    scopes: set[AuthScope]


bearer_scheme = HTTPBearer(
    scheme_name="ControlPlaneAPIKey",
    description="Scoped AgentEval API key or configured OIDC access token.",
    bearerFormat="API key or JWT",
    auto_error=False,
)


def hash_api_key(secret: str) -> str:
    if not secret:
        raise ValueError("API key must not be empty")
    return hashlib.sha256(secret.encode()).hexdigest()


def load_auth_config(path: Path) -> AuthConfig:
    payload = yaml.safe_load(path.read_text())
    config = AuthConfig.model_validate(payload)
    key_ids = [key.key_id for key in config.keys]
    if len(key_ids) != len(set(key_ids)):
        raise ValueError("authentication key IDs must be unique")
    digests = [key.secret_sha256 for key in config.keys]
    if len(digests) != len(set(digests)):
        raise ValueError("authentication key digests must be unique")
    return config


class Authenticator:
    def __init__(
        self,
        config_path: str | Path | None = None,
        *,
        credential_lookup: Callable[[str], ResolvedTenantAPIKey | None] | None = None,
        tenant_access_allowed: Callable[[str], bool] | None = None,
        federated_token_verifier: FederatedTokenVerifier | None = None,
    ) -> None:
        resolved = config_path or os.getenv("AECONTROL_AUTH_CONFIG")
        self.config_path = Path(resolved) if resolved else None
        self.config = load_auth_config(self.config_path) if self.config_path else None
        self.credential_lookup = credential_lookup
        self.tenant_access_allowed = tenant_access_allowed
        self.federated_token_verifier = (
            federated_token_verifier
            if federated_token_verifier is not None
            else OIDCFederatedTokenVerifier.from_environment()
        )

    @property
    def enabled(self) -> bool:
        return self.config is not None or self.federated_token_verifier is not None

    def require(self, scope: AuthScope) -> Callable[..., Awaitable[Principal]]:
        async def authenticate(
            request: Request,
            credentials: Annotated[
                HTTPAuthorizationCredentials | None, Security(bearer_scheme)
            ] = None,
        ) -> Principal:
            if not self.enabled:
                principal = Principal(
                    key_id="local-trust", tenant_id=default_tenant_id(), scopes={"admin"}
                )
                bind_tenant(principal.tenant_id)
                request.state.principal = principal
                return principal
            if credentials is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Bearer credential is required",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            candidate = hash_api_key(credentials.credentials)
            key = next(
                (
                    configured
                    for configured in (self.config.keys if self.config is not None else [])
                    if hmac.compare_digest(configured.secret_sha256, candidate)
                ),
                None,
            )
            resolved_key = self.credential_lookup(candidate) if self.credential_lookup else None
            federated_identity = None
            if (
                key is None
                and resolved_key is None
                and self.federated_token_verifier is not None
                and credentials.credentials.count(".") == 2
            ):
                with suppress(FederationError):
                    federated_identity = await asyncio.to_thread(
                        self.federated_token_verifier.verify, credentials.credentials
                    )
            if key is None and resolved_key is None and federated_identity is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Bearer credential is invalid",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            if key is not None:
                tenant_id = key.tenant_id
                key_id = key.key_id
                scopes = key.scopes
                if (
                    "operator" not in scopes
                    and self.tenant_access_allowed is not None
                    and not self.tenant_access_allowed(tenant_id)
                ):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Bearer credential is invalid",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
            elif resolved_key is not None:
                assert resolved_key is not None
                tenant_id = resolved_key.tenant_id
                key_id = resolved_key.key_id
                scopes = set(resolved_key.scopes)
            else:
                assert federated_identity is not None
                tenant_id = federated_identity.tenant_id
                key_id = federated_identity.principal_id
                scopes = set(federated_identity.scopes)
                if self.tenant_access_allowed is not None and not self.tenant_access_allowed(
                    tenant_id
                ):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Bearer credential is invalid",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
            authorized = scope in scopes or (scope != "operator" and "admin" in scopes)
            if not authorized:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Bearer credential requires the {scope} scope",
                )
            principal = Principal(key_id=key_id, tenant_id=tenant_id, scopes=scopes)
            bind_tenant(principal.tenant_id)
            request.state.principal = principal
            return principal

        return authenticate
