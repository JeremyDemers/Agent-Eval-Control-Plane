# Tenant Lifecycle

Schema v15 adds a control-plane tenant registry and self-service API-key rotation while preserving
PostgreSQL row-level security for evaluation evidence. Static YAML credentials remain the bootstrap
and break-glass mechanism; a static key with the isolated `operator` scope provisions and controls
tenants but cannot read tenant evidence.

```yaml
keys:
  - key_id: platform-operator
    tenant_id: control-plane
    secret_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    scopes: [operator]
```

`operator` cannot be combined with `read`, `write`, or `admin`. Conversely, a tenant `admin` cannot
list or modify other tenants. This separation prevents a routine tenant credential from becoming a
fleet-wide identity.

## Provision And Rotate

Provisioning creates the tenant and its first admin credential in one transaction. The plaintext
secret is generated with the operating system CSPRNG, returned once, and never persisted. PostgreSQL
stores only its SHA-256 digest. Issuance responses include `Cache-Control: no-store`.

```bash
curl -X POST http://127.0.0.1:8000/api/v1/platform/tenants \
  -H "Authorization: Bearer $AECONTROL_OPERATOR_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"research","display_name":"Agent Research","initial_key_id":"admin-v1"}'

curl -X POST http://127.0.0.1:8000/api/v1/tenant/api-keys \
  -H "Authorization: Bearer $AECONTROL_TENANT_ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"key_id":"admin-v2","scopes":["admin"]}'

curl -X DELETE http://127.0.0.1:8000/api/v1/tenant/api-keys/admin-v1 \
  -H "Authorization: Bearer $AECONTROL_TENANT_ADMIN_KEY"
```

Tenant admins may issue `read`, `write`, or `admin` credentials only inside their resolved tenant.
Key IDs are tenant-local, credential digests are globally unique, revoked keys remain as metadata,
and no API response contains a digest. Revocation locks the tenant row and refuses to remove the last
active admin, making concurrent rotations deterministic.

The synchronous and asynchronous SDKs expose matching `create_tenant`, `tenants`, `tenant`,
`set_tenant_status`, `tenant_api_keys`, `issue_tenant_api_key`, and `revoke_tenant_api_key` methods.

## Suspension

An operator suspends or reactivates a tenant through
`PATCH /api/v1/platform/tenants/{tenant_id}` with `{"status":"suspended"}` or
`{"status":"active"}`. Authentication joins dynamic credentials to tenant status and fails closed
while suspended. Static tenant keys are also denied when their tenant has a lifecycle record in the
suspended state. The static operator remains able to reactivate the tenant.

Existing YAML-only tenants have no registry row and remain active for backward compatibility. They
can continue using static credentials but do not gain self-service key management until provisioned.

## Trust Boundary

The `control_plane_tenants` and `tenant_api_keys` tables intentionally do not use tenant RLS:
credential resolution happens before a tenant can be bound to the database transaction, and platform
operators need global lifecycle inventory. They are reachable through application methods guarded by
`operator` or tenant-local `admin`, but the application database role can read their digests. Database
credentials therefore remain a trusted operator asset and should be isolated from tenant workloads.

Schema v17 adds resource quotas through a separate operator-owned policy table; see
[`tenant-quotas.md`](tenant-quotas.md). OIDC federation can authenticate registered tenants but does
not change lifecycle ownership; see [`identity-federation.md`](identity-federation.md). The registry
does not provide billing, invitation workflows, or automatic worker-pool provisioning. Production deployments should keep the
bootstrap operator key in a secret manager, rotate it through configuration rollout, terminate TLS
before the API, and audit operator requests through the structured key ID and request ID logs.
