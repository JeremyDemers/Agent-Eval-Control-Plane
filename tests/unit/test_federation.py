from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from aecontrol.federation import (
    FederationError,
    OIDCFederatedTokenVerifier,
    OIDCFederationConfiguration,
    oidc_configuration_from_environment,
)


class StaticSigningKeyClient:
    def __init__(self, key: jwt.PyJWK) -> None:
        self.key = key
        self.tokens: list[str] = []

    def get_signing_key_from_jwt(self, token: str) -> jwt.PyJWK:
        self.tokens.append(token)
        return self.key


@pytest.fixture
def signing_material():  # type: ignore[no-untyped-def]
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    jwk = jwt.PyJWK.from_dict(
        {
            "kty": "RSA",
            "kid": "rotation-2026-07",
            "use": "sig",
            "alg": "RS256",
            "n": _base64url_uint(numbers.n),
            "e": _base64url_uint(numbers.e),
        }
    )
    return private_key, jwk


def _configuration(**updates: object) -> OIDCFederationConfiguration:
    values: dict[str, object] = {
        "issuer": "https://identity.example/realms/agents",
        "audiences": ("aecontrol-api",),
        "jwks_url": "https://identity.example/realms/agents/jwks",
    }
    values.update(updates)
    return OIDCFederationConfiguration.model_validate(values)


def _token(private_key, **claim_updates: object) -> str:  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": "https://identity.example/realms/agents",
        "aud": "aecontrol-api",
        "sub": "service-account:release-evaluator",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "aecontrol_tenant": "research",
        "scope": "openid profile aecontrol:read aecontrol:write",
    }
    claims.update(claim_updates)
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": "rotation-2026-07"},
    )


def test_oidc_configuration_is_explicit_bounded_and_asymmetric(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    for name in (
        "AECONTROL_OIDC_ISSUER",
        "AECONTROL_OIDC_AUDIENCE",
        "AECONTROL_OIDC_JWKS_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    assert oidc_configuration_from_environment() is None

    monkeypatch.setenv("AECONTROL_OIDC_ISSUER", "https://identity.example")
    with pytest.raises(ValueError, match="incomplete OIDC configuration"):
        oidc_configuration_from_environment()
    monkeypatch.setenv("AECONTROL_OIDC_AUDIENCE", "api-one,api-two")
    monkeypatch.setenv("AECONTROL_OIDC_JWKS_URL", "https://identity.example/jwks")
    monkeypatch.setenv("AECONTROL_OIDC_ALGORITHMS", "RS256,ES256")
    configured = oidc_configuration_from_environment()
    assert configured is not None
    assert configured.audiences == ("api-one", "api-two")
    assert configured.algorithms == ("RS256", "ES256")

    with pytest.raises(ValidationError, match="HTTPS or loopback HTTP"):
        _configuration(jwks_url="http://identity.example/jwks")
    with pytest.raises(ValidationError, match="asymmetric allowlist"):
        _configuration(algorithms=("HS256",))
    with pytest.raises(ValidationError, match="must be unique"):
        _configuration(audiences=("aecontrol-api", "aecontrol-api"))
    with pytest.raises(ValidationError, match="must be different"):
        _configuration(tenant_claim="identity", scope_claim="identity")
    with pytest.raises(ValidationError):
        _configuration(scope_prefix="generic")
    assert _configuration(jwks_url="http://127.0.0.1:9000/jwks").issuer_host == ("identity.example")


def test_verifier_validates_signature_registered_claims_tenant_and_scopes(
    signing_material,  # type: ignore[no-untyped-def]
) -> None:
    private_key, key = signing_material
    key_client = StaticSigningKeyClient(key)
    verifier = OIDCFederatedTokenVerifier(_configuration(), key_client)
    token = _token(private_key)

    identity = verifier.verify(token)

    assert identity.tenant_id == "research"
    assert identity.scopes == {"read", "write"}
    assert identity.principal_id.startswith("oidc:")
    assert "release-evaluator" not in identity.principal_id
    assert key_client.tokens == [token]


@pytest.mark.parametrize(
    ("claim_updates", "message"),
    [
        ({"iss": "https://attacker.example"}, "validation failed"),
        ({"aud": "another-api"}, "validation failed"),
        ({"exp": datetime.now(UTC) - timedelta(minutes=1)}, "validation failed"),
        ({"aecontrol_tenant": "Other/Tenant"}, "tenant claim is invalid"),
        ({"scope": "openid profile"}, "no AgentEval scopes"),
        ({"scope": "aecontrol:operator"}, "cannot receive operator"),
    ],
)
def test_verifier_rejects_invalid_boundaries(
    signing_material,  # type: ignore[no-untyped-def]
    claim_updates: dict[str, object],
    message: str,
) -> None:
    private_key, key = signing_material
    verifier = OIDCFederatedTokenVerifier(_configuration(), StaticSigningKeyClient(key))

    with pytest.raises(FederationError, match=message):
        verifier.verify(_token(private_key, **claim_updates))


def test_verifier_supports_array_scopes_and_requires_claims(
    signing_material,  # type: ignore[no-untyped-def]
) -> None:
    private_key, key = signing_material
    verifier = OIDCFederatedTokenVerifier(_configuration(), StaticSigningKeyClient(key))

    identity = verifier.verify(
        _token(private_key, scope=["profile", "aecontrol:admin", "unrelated:operator"])
    )
    assert identity.scopes == {"admin"}

    now = datetime.now(UTC)
    missing_expiry = jwt.encode(
        {
            "iss": _configuration().issuer,
            "aud": "aecontrol-api",
            "sub": "workload",
            "iat": now,
            "aecontrol_tenant": "research",
            "scope": "aecontrol:read",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "rotation-2026-07"},
    )
    with pytest.raises(FederationError, match="validation failed"):
        verifier.verify(missing_expiry)


def test_verifier_rejects_header_abuse_before_jwks_fetch(
    signing_material,  # type: ignore[no-untyped-def]
) -> None:
    private_key, key = signing_material
    key_client = StaticSigningKeyClient(key)
    verifier = OIDCFederatedTokenVerifier(_configuration(), key_client)
    now = datetime.now(UTC)
    claims = {
        "iss": _configuration().issuer,
        "aud": "aecontrol-api",
        "sub": "workload",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "aecontrol_tenant": "research",
        "scope": "aecontrol:read",
    }
    missing_key_id = jwt.encode(claims, private_key, algorithm="RS256")
    with pytest.raises(FederationError, match="missing a key ID"):
        verifier.verify(missing_key_id)
    disallowed_algorithm = jwt.encode(
        claims,
        "not-a-production-secret-that-is-long-enough",
        algorithm="HS256",
        headers={"kid": "symmetric"},
    )
    with pytest.raises(FederationError, match="algorithm is not allowed"):
        verifier.verify(disallowed_algorithm)
    with pytest.raises(FederationError, match="too large"):
        verifier.verify("a" * 16_385)
    assert key_client.tokens == []


def _base64url_uint(value: int) -> str:
    size = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()
