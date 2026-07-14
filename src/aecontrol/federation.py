from __future__ import annotations

import hashlib
import os
from collections.abc import Sequence
from typing import Literal, Protocol, cast
from urllib.parse import urlparse

import jwt
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError, PyJWKClientError
from pydantic import BaseModel, ConfigDict, Field, model_validator

from aecontrol.tenancy import TENANT_ID_PATTERN, validate_tenant_id

FederatedScope = Literal["read", "write", "admin"]
ALLOWED_ASYMMETRIC_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"}
)
CLAIM_NAME_PATTERN = r"^[A-Za-z_][A-Za-z0-9_.:-]{0,99}$"


class FederationError(RuntimeError):
    pass


class OIDCFederationConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer: str = Field(min_length=1, max_length=500)
    audiences: tuple[str, ...] = Field(min_length=1, max_length=10)
    jwks_url: str = Field(min_length=1, max_length=1000)
    algorithms: tuple[str, ...] = Field(default=("RS256",), min_length=1, max_length=10)
    tenant_claim: str = Field(default="aecontrol_tenant", pattern=CLAIM_NAME_PATTERN)
    scope_claim: str = Field(default="scope", pattern=CLAIM_NAME_PATTERN)
    scope_prefix: str = Field(default="aecontrol:", pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,62}[:./]$")
    jwks_timeout_seconds: float = Field(default=2, ge=0.1, le=10)
    jwks_cache_seconds: float = Field(default=300, ge=60, le=3600)
    clock_skew_seconds: float = Field(default=5, ge=0, le=60)

    @model_validator(mode="after")
    def validate_security_boundaries(self) -> OIDCFederationConfiguration:
        _validate_federation_url(self.issuer, "issuer")
        _validate_federation_url(self.jwks_url, "JWKS URL")
        if not self.algorithms or any(
            algorithm not in ALLOWED_ASYMMETRIC_ALGORITHMS for algorithm in self.algorithms
        ):
            raise ValueError("OIDC algorithms must use the supported asymmetric allowlist")
        if len(set(self.algorithms)) != len(self.algorithms):
            raise ValueError("OIDC algorithms must be unique")
        if self.tenant_claim == self.scope_claim:
            raise ValueError("OIDC tenant and scope claims must be different")
        if len(set(self.audiences)) != len(self.audiences) or any(
            not audience or len(audience) > 500 for audience in self.audiences
        ):
            raise ValueError("OIDC audiences must be unique non-empty values")
        return self

    @property
    def issuer_host(self) -> str:
        return urlparse(self.issuer).hostname or "unknown"


class FederatedIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    principal_id: str = Field(pattern=r"^oidc:[a-f0-9]{20}$")
    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    scopes: set[FederatedScope] = Field(min_length=1)


class SigningKeyClient(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> jwt.PyJWK: ...


class FederatedTokenVerifier(Protocol):
    def verify(self, token: str) -> FederatedIdentity: ...


def oidc_configuration_from_environment() -> OIDCFederationConfiguration | None:
    required = {
        "issuer": os.getenv("AECONTROL_OIDC_ISSUER"),
        "audiences": os.getenv("AECONTROL_OIDC_AUDIENCE"),
        "jwks_url": os.getenv("AECONTROL_OIDC_JWKS_URL"),
    }
    if not any(required.values()):
        return None
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ValueError(f"incomplete OIDC configuration; missing: {', '.join(missing)}")
    assert required["issuer"] is not None
    assert required["audiences"] is not None
    assert required["jwks_url"] is not None
    return OIDCFederationConfiguration(
        issuer=required["issuer"],
        audiences=_comma_separated(required["audiences"]),
        jwks_url=required["jwks_url"],
        algorithms=_comma_separated(os.getenv("AECONTROL_OIDC_ALGORITHMS", "RS256")),
        tenant_claim=os.getenv("AECONTROL_OIDC_TENANT_CLAIM", "aecontrol_tenant"),
        scope_claim=os.getenv("AECONTROL_OIDC_SCOPE_CLAIM", "scope"),
        scope_prefix=os.getenv("AECONTROL_OIDC_SCOPE_PREFIX", "aecontrol:"),
        jwks_timeout_seconds=float(os.getenv("AECONTROL_OIDC_JWKS_TIMEOUT_SECONDS", "2")),
        jwks_cache_seconds=float(os.getenv("AECONTROL_OIDC_JWKS_CACHE_SECONDS", "300")),
        clock_skew_seconds=float(os.getenv("AECONTROL_OIDC_CLOCK_SKEW_SECONDS", "5")),
    )


class OIDCFederatedTokenVerifier:
    def __init__(
        self,
        configuration: OIDCFederationConfiguration,
        signing_key_client: SigningKeyClient | None = None,
    ) -> None:
        self.configuration = configuration
        self.signing_key_client = signing_key_client or PyJWKClient(
            configuration.jwks_url,
            cache_keys=True,
            max_cached_keys=16,
            cache_jwk_set=True,
            lifespan=configuration.jwks_cache_seconds,
            timeout=configuration.jwks_timeout_seconds,
        )

    @classmethod
    def from_environment(cls) -> OIDCFederatedTokenVerifier | None:
        configuration = oidc_configuration_from_environment()
        return cls(configuration) if configuration is not None else None

    def verify(self, token: str) -> FederatedIdentity:
        if len(token) > 16_384:
            raise FederationError("federated token is too large")
        try:
            header = jwt.get_unverified_header(token)
            algorithm = header.get("alg")
            key_id = header.get("kid")
            if algorithm not in self.configuration.algorithms:
                raise FederationError("federated token algorithm is not allowed")
            if not isinstance(key_id, str) or not key_id:
                raise FederationError("federated token is missing a key ID")
            signing_key = self.signing_key_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=list(self.configuration.algorithms),
                audience=list(self.configuration.audiences),
                issuer=self.configuration.issuer,
                leeway=self.configuration.clock_skew_seconds,
                options={"require": ["exp", "iat", "sub"]},
            )
            return self._identity_from_claims(claims)
        except FederationError:
            raise
        except (InvalidTokenError, PyJWKClientError, OverflowError, TypeError, ValueError) as error:
            raise FederationError("federated token validation failed") from error

    def _identity_from_claims(self, claims: dict[str, object]) -> FederatedIdentity:
        subject = claims.get("sub")
        tenant = claims.get(self.configuration.tenant_claim)
        if not isinstance(subject, str) or not subject or len(subject) > 500:
            raise FederationError("federated token subject is invalid")
        if not isinstance(tenant, str):
            raise FederationError("federated token tenant claim is invalid")
        try:
            tenant_id = validate_tenant_id(tenant)
        except ValueError as error:
            raise FederationError("federated token tenant claim is invalid") from error
        scopes = self._scopes(claims.get(self.configuration.scope_claim))
        principal_digest = hashlib.sha256(
            f"{self.configuration.issuer}\0{subject}".encode()
        ).hexdigest()[:20]
        return FederatedIdentity(
            principal_id=f"oidc:{principal_digest}", tenant_id=tenant_id, scopes=scopes
        )

    def _scopes(self, raw_scopes: object) -> set[FederatedScope]:
        values: Sequence[object]
        if isinstance(raw_scopes, str):
            values = raw_scopes.split()
        elif isinstance(raw_scopes, list):
            values = raw_scopes
        else:
            raise FederationError("federated token scope claim is invalid")
        if len(values) > 100:
            raise FederationError("federated token scope claim is invalid")
        mapped: set[FederatedScope] = set()
        for raw_scope in values:
            if not isinstance(raw_scope, str) or len(raw_scope) > 200:
                raise FederationError("federated token scope claim is invalid")
            if not raw_scope.startswith(self.configuration.scope_prefix):
                continue
            scope = raw_scope.removeprefix(self.configuration.scope_prefix)
            if scope == "operator":
                raise FederationError("federated tokens cannot receive operator scope")
            if scope in {"read", "write", "admin"}:
                mapped.add(cast(FederatedScope, scope))
        if not mapped:
            raise FederationError("federated token has no AgentEval scopes")
        return mapped


def _validate_federation_url(value: str, label: str) -> None:
    parsed = urlparse(value)
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme not in ({"http", "https"} if loopback else {"https"}) or not parsed.netloc:
        raise ValueError(f"OIDC {label} must be HTTPS or loopback HTTP")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError(f"OIDC {label} must not include credentials or a fragment")


def _comma_separated(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())
