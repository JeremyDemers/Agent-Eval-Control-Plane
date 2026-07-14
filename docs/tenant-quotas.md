# Tenant Resource Quotas

Schema v17 adds operator-managed limits for multi-tenant evaluation capacity. Policies are optional;
an omitted limit is unlimited, while zero deliberately pauses that resource class without suspending
the tenant or revoking its credentials.

| Limit | Enforcement point | Usage definition |
| --- | --- | --- |
| `max_queued_jobs` | Job submission | Jobs currently in `queued` state |
| `max_jobs_per_hour` | Job submission | All jobs created in the rolling previous hour |
| `max_running_jobs` | Worker lease | Running jobs whose leases have not expired |
| `max_running_cuda_jobs` | Worker lease | Active running jobs requiring CUDA |

The CUDA limit cannot exceed the total running limit. Lowering a policy does not cancel queued work
or terminate active leases; it prevents subsequent submissions or claims until usage returns below
the new boundary. Expired leases do not consume concurrency, allowing recovery workers to reclaim
abandoned jobs.

## API

Only an isolated `operator` credential can read or replace another tenant's policy:

```bash
curl -X PUT http://127.0.0.1:8000/api/v1/platform/tenants/research/quota \
  -H "Authorization: Bearer $OPERATOR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "max_queued_jobs": 200,
    "max_jobs_per_hour": 1000,
    "max_running_jobs": 16,
    "max_running_cuda_jobs": 4
  }'
```

Tenant credentials with `read` scope can inspect their own policy and live usage without selecting a
tenant through the path or payload:

```bash
curl http://127.0.0.1:8000/api/v1/tenant/quota \
  -H "Authorization: Bearer $TENANT_API_KEY"
```

Rejected submissions return HTTP 429 with stable structured detail:

```json
{
  "detail": {
    "code": "tenant_quota_exceeded",
    "quota": "max_queued_jobs",
    "limit": 200,
    "observed": 201
  }
}
```

Worker lease saturation returns no claim, preserving the existing polling contract. If the CUDA
limit is saturated, a mixed-capability worker can still claim an eligible CPU job even when a
higher-priority CUDA job is waiting.

## CLI and SDK

Database operators can replace a complete policy from the CLI. Omitted options become unlimited:

```bash
uv run aecontrol tenant quota-set research \
  --max-queued-jobs 200 \
  --max-jobs-per-hour 1000 \
  --max-running-jobs 16 \
  --max-running-cuda-jobs 4 \
  --updated-by capacity-controller

AECONTROL_TENANT_ID=research uv run aecontrol tenant quota-status
```

The synchronous and asynchronous SDKs expose `tenant_quota`, `set_tenant_quota`, and
`current_tenant_quota` using `TenantQuotaLimits`, `TenantQuotaRecord`, and `TenantQuotaStatus`.

## Concurrency and Isolation

Submission checks and inserts share a transaction-scoped PostgreSQL advisory lock derived from the
schema and authenticated tenant. Worker usage checks and `FOR UPDATE SKIP LOCKED` claims use the same
lock. Multiple API replicas and workers therefore serialize only within one tenant; unrelated tenants
continue concurrently.

Job counts execute under the transaction-local tenant identity and forced RLS policy. The quota and
tenant registries remain outside RLS because an operator must configure policy before tenant context
is available, but tenant-facing usage never accepts an arbitrary tenant identifier. Policies do not
reserve physical GPUs or replace Kubernetes device isolation; they govern AgentEval queue admission
and leases.
