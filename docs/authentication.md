# API Authentication

AgentEval supports optional scoped bearer keys and federated JWTs for `/api/v1` endpoints.
Authentication is disabled for the zero-configuration local demo and enabled when
`AECONTROL_AUTH_CONFIG` points to a YAML file or complete OIDC environment configuration is present.
Health, readiness, API documentation, and the local browser explorer remain public so operators can
diagnose the service and inspect the portfolio demo.

## Create a key

Generate a high-entropy secret with your preferred secret manager, then hash it without placing the
plaintext value in the configuration:

```bash
uv run aecontrol auth hash-key
```

Create `auth.yaml` with the printed SHA-256 digest:

```yaml
keys:
  - key_id: automation
    tenant_id: platform
    secret_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    scopes: [read, write]
  - key_id: auditor
    tenant_id: safety
    secret_sha256: abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    scopes: [read]
```

Validate and start the service:

```bash
uv run aecontrol auth validate auth.yaml
AECONTROL_AUTH_CONFIG=auth.yaml make serve
curl -H "Authorization: Bearer $AECONTROL_API_KEY" http://127.0.0.1:8000/api/v1/runs
```

The typed synchronous and asynchronous SDK clients accept `api_key=` and also read
`AECONTROL_API_KEY`, allowing the plaintext credential to remain in the deployment secret provider.

Tenant identity is bound to the key configuration and cannot be selected through a request header.
Authenticated responses include `X-AEControl-Tenant`; omitted tenant IDs use `default` for backward
compatibility. See [`multi-tenancy.md`](multi-tenancy.md) for PostgreSQL RLS enforcement, worker
binding, migration behavior, and the database-role trust boundary.

`read` permits API queries, `write` permits evaluation, queue, cancellation, and comparison
operations, and `admin` satisfies every scope within the key's tenant. Guardrails configuration
registration and activation specifically require `admin`; activation history and version inventory
require `read`. Keys should be random and rotated through the
deployment secret manager; the service keeps static digests in memory and never logs bearer
credentials. Dynamically issued key digests remain in PostgreSQL as described below.

## Bootstrap operator and dynamic keys

Schema v15 supports persisted tenant credentials in addition to static YAML credentials. Configure a
bootstrap key with `scopes: [operator]` to provision, suspend, and reactivate tenants. `operator` is an
isolated cross-tenant lifecycle scope: it cannot be combined with tenant scopes and does not authorize
access to runs, jobs, comparisons, guardrails evidence, or integrity reports.

Provisioning returns a generated plaintext tenant-admin key exactly once. Subsequent tenant keys are
created and revoked by that tenant's `admin` credentials. Dynamic digests are stored in PostgreSQL;
they are never returned, logged, or loaded into the static configuration. The final active admin key
cannot be revoked. See [`tenant-lifecycle.md`](tenant-lifecycle.md) for endpoints, SDK methods,
suspension behavior, and rotation examples.

## OIDC federation

Signed JWT access tokens can coexist with static and dynamic API keys. Federation requires explicit
issuer, audience, and JWKS configuration; maps only namespaced tenant scopes; and never grants the
bootstrap `operator` permission. SDK clients pass the access token through the existing `api_key`
argument or `AECONTROL_API_KEY`. See [`identity-federation.md`](identity-federation.md) for the claim
contract, bounded key caching, diagnostics, rotation, and revocation behavior.
