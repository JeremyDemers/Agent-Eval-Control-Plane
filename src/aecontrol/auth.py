from __future__ import annotations

import hashlib
import hmac
import os
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Literal

import yaml
from fastapi import HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

AuthScope = Literal["read", "write", "admin"]


class APIKey(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str = Field(min_length=1, max_length=64)
    secret_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    scopes: set[AuthScope] = Field(min_length=1)


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    keys: list[APIKey] = Field(min_length=1)


class Principal(BaseModel):
    key_id: str
    scopes: set[AuthScope]


bearer_scheme = HTTPBearer(
    scheme_name="ControlPlaneAPIKey",
    description="Scoped API key issued by the AgentEval control-plane operator.",
    bearerFormat="API key",
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
    def __init__(self, config_path: str | Path | None = None) -> None:
        resolved = config_path or os.getenv("AECONTROL_AUTH_CONFIG")
        self.config_path = Path(resolved) if resolved else None
        self.config = load_auth_config(self.config_path) if self.config_path else None

    @property
    def enabled(self) -> bool:
        return self.config is not None

    def require(self, scope: AuthScope) -> Callable[..., Principal]:
        def authenticate(
            request: Request,
            credentials: Annotated[
                HTTPAuthorizationCredentials | None, Security(bearer_scheme)
            ] = None,
        ) -> Principal:
            if self.config is None:
                principal = Principal(key_id="local-trust", scopes={"admin"})
                request.state.principal = principal
                return principal
            if credentials is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="API key is required",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            candidate = hash_api_key(credentials.credentials)
            key = next(
                (
                    configured
                    for configured in self.config.keys
                    if hmac.compare_digest(configured.secret_sha256, candidate)
                ),
                None,
            )
            if key is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="API key is invalid",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            if scope not in key.scopes and "admin" not in key.scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"API key requires the {scope} scope",
                )
            principal = Principal(key_id=key.key_id, scopes=key.scopes)
            request.state.principal = principal
            return principal

        return authenticate
