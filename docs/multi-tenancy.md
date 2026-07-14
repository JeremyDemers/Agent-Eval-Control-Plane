# Tenant Isolation

AgentEval binds every authenticated API key to exactly one tenant. Identity comes from an
operator-owned static configuration or the schema v15 credential registry, never a caller-supplied
header, so a credential cannot request another organization's namespace. `admin` is tenant-local: it
satisfies API scopes inside the key's tenant but does not grant cross-tenant inventory or
impersonation. The separate static `operator` scope manages lifecycle state but cannot read tenant
evidence.

```yaml
keys:
  - key_id: platform-automation
    tenant_id: platform
    secret_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    scopes: [admin]
  - key_id: safety-auditor
    tenant_id: safety
    secret_sha256: abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    scopes: [read]
```

Successful authenticated responses include `X-AEControl-Tenant` so clients can verify the resolved
boundary. Configurations without `tenant_id` remain in the `default` tenant for backward compatibility.
Tenant IDs are lowercase, 1-64 character slugs containing letters, digits, dots, underscores, and
hyphens.

## PostgreSQL Enforcement

Schema v12 adds `tenant_id` to evaluation runs, comparisons, guardrail evidence and policy history,
jobs, and workers. Each table has:

- Enabled and forced PostgreSQL row-level security.
- A policy matching `tenant_id` to transaction-local `aecontrol.tenant_id` for reads and writes.
- A tenant index and a database check for the normalized tenant ID format.
- Tenant-aware run, job, comparison, policy-version, and activation relationships.

The API authentication dependency binds tenant context before endpoint execution. Every direct or
pooled store transaction then calls `set_config(..., true)`, limiting the setting to that transaction
and preventing connection-pool reuse from carrying identity into another request. Existing rows are
migrated to `default`. The integration suite creates a non-superuser table-owning role and proves that
two tenants can reuse a policy name while neither can list or fetch the other's jobs.

The application database role must not be a PostgreSQL superuser and must not have `BYPASSRLS`.
`FORCE ROW LEVEL SECURITY` covers the normal table owner, but PostgreSQL superusers always bypass RLS.
Database credentials are therefore an operator trust boundary and must never be issued to API tenants.

## Workers And Scaling

CLI and worker processes bind `AECONTROL_TENANT_ID`, defaulting to `default`. A worker can claim only
jobs and publish only inventory in its bound tenant. Deploy a separate worker pool per tenant when
organizations must not share execution capacity or signing keys.

The repository Kubernetes base explicitly binds API and worker pods to `default`. Environment
overlays should patch `AECONTROL_TENANT_ID` alongside tenant-specific labels and secrets. The KEDA
example establishes the same transaction-local default tenant inside each PostgreSQL scaler query;
clone and patch both the worker deployment and scaler query when creating another tenant's pool.

Unauthenticated health, readiness, metrics, and browser routes remain operational surfaces for the
deployment's `AECONTROL_TENANT_ID`; they are not cross-tenant aggregate views. Schema v15 provides
atomic tenant provisioning, suspension, reactivation, self-service key rotation, and global lifecycle
inventory. The lifecycle and credential tables deliberately sit outside tenant RLS because identity
must be resolved before tenant context exists; only operator and tenant-admin API methods expose them.
See [`tenant-lifecycle.md`](tenant-lifecycle.md) for that database trust boundary. Schema v17 adds
queue and execution quotas; see [`tenant-quotas.md`](tenant-quotas.md). Billing, automatic worker
provisioning, and cross-tenant analytics remain outside the current boundary.

Federated JWTs bind the validated tenant claim into this same transaction context; they do not add a
second authorization path around RLS. See [`identity-federation.md`](identity-federation.md).
