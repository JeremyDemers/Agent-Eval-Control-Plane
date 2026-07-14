# OIDC Identity Federation

AgentEval accepts signed JWT access tokens from one explicitly configured OpenID Connect issuer while
retaining static and dynamically issued API keys. Federation removes long-lived AgentEval secrets
from ordinary user and workload access; the isolated platform `operator` remains a static bootstrap
credential and can never be granted by a federated token.

## Configuration

Set all three required values or startup fails closed:

```bash
export AECONTROL_OIDC_ISSUER=https://identity.example/realms/agents
export AECONTROL_OIDC_AUDIENCE=aecontrol-api
export AECONTROL_OIDC_JWKS_URL=https://identity.example/realms/agents/protocol/openid-connect/certs

uv run aecontrol auth federation
AECONTROL_AUTH_CONFIG=auth.yaml uv run aecontrol serve
```

The issuer and JWKS endpoint require HTTPS. Loopback HTTP is accepted only for local identity-provider
testing. URLs containing credentials or fragments are rejected. `AECONTROL_OIDC_AUDIENCE` accepts a
comma-separated allowlist when multiple deployment audiences are necessary.

Optional bounded settings:

| Variable | Default | Boundary |
| --- | --- | --- |
| `AECONTROL_OIDC_ALGORITHMS` | `RS256` | Comma-separated asymmetric allowlist |
| `AECONTROL_OIDC_TENANT_CLAIM` | `aecontrol_tenant` | Top-level tenant claim |
| `AECONTROL_OIDC_SCOPE_CLAIM` | `scope` | String or JSON-array scope claim |
| `AECONTROL_OIDC_SCOPE_PREFIX` | `aecontrol:` | Namespace required for mapped scopes |
| `AECONTROL_OIDC_JWKS_TIMEOUT_SECONDS` | `2` | 0.1 to 10 seconds |
| `AECONTROL_OIDC_JWKS_CACHE_SECONDS` | `300` | 60 to 3600 seconds |
| `AECONTROL_OIDC_CLOCK_SKEW_SECONDS` | `5` | 0 to 60 seconds |

Accepted algorithms are restricted to asymmetric RSA, ECDSA, or EdDSA variants. Symmetric HMAC JWTs
are rejected because an API verifier holding the shared secret could also mint identities. The token
header algorithm must appear in the configured allowlist before AgentEval contacts JWKS.

## Token Contract

A valid token must contain:

- A signature matching the JWKS key selected by a non-empty `kid`
- Exact configured `iss` and one configured `aud`
- `exp`, `iat`, and non-empty `sub` registered claims
- A tenant slug in the configured tenant claim
- At least one namespaced `aecontrol:read`, `aecontrol:write`, or `aecontrol:admin` scope

Generic provider scopes such as `openid`, `profile`, or `admin` do not grant AgentEval permissions.
An explicit `aecontrol:operator` scope rejects the entire token. The subject is never logged directly;
AgentEval records a stable 20-hex SHA-256 pseudonym bound to issuer and subject for audit attribution.

Bearer authentication first performs constant-time static and dynamic API-key lookup. Only an
unrecognized credential with three JWT segments enters federation verification. This preserves API
key rotation and avoids JWKS traffic for ordinary invalid opaque keys.

## Tenant Boundary

The verified tenant claim becomes the same transaction-local identity used by API-key principals.
Forced PostgreSQL RLS, tenant-aware foreign keys, worker pools, quotas, evidence signatures, and
ledger operations therefore retain their existing boundary. Request headers, paths, and payloads
cannot override the claim.

Registered tenant suspension is checked on every federated request and denies access immediately.
Existing YAML-only tenants remain available for backward compatibility. Provision tenants with the
static `operator` before relying on self-service quota and key APIs.

## Rotation and Failure Behavior

AgentEval caches the bounded JWKS document and up to 16 parsed signing keys. A new `kid` causes the
client to refresh keys, supporting normal identity-provider rotation without application restart.
JWKS timeouts, malformed responses, unknown keys, invalid claims, and signature failures all return
the same HTTP 401 response; internal verification details are not exposed to callers.

Federation uses local JWT validation rather than token introspection. A token remains usable until
its expiry unless the tenant is suspended or the issuer removes the signing key and the local JWKS
cache refreshes. Use short access-token lifetimes for rapid user revocation. AgentEval does not accept
opaque provider access tokens or browser refresh tokens.

The implementation uses PyJWT's [JWKS client](https://pyjwt.readthedocs.io/en/stable/usage.html#retrieve-rsa-signing-keys-from-a-jwks-endpoint)
with explicit algorithm selection following the [JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html).
