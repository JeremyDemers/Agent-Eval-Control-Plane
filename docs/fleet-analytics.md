# Privacy-Bounded Fleet Analytics

Schema v18 gives platform operators a cross-tenant capacity view without granting access to tenant
evaluation evidence. `GET /api/v1/platform/fleet` requires the static `operator` scope and reports:

- Queued and actively leased CPU/CUDA jobs.
- Workers observed in the last 24 hours and workers active in a bounded 30-3600 second window.
- GPU devices advertised by active CUDA workers.
- Oldest queued-job age, tenant lifecycle state, quota limits, and quota saturation.

```bash
curl -H "Authorization: Bearer $AECONTROL_OPERATOR_KEY" \
  "http://127.0.0.1:8000/api/v1/platform/fleet?active_worker_window_seconds=120"

uv run aecontrol platform fleet --json
```

The synchronous and asynchronous SDKs expose the same contract through
`platform_fleet(active_worker_window_seconds=120)`.

## Data Boundary

The endpoint never reads tenant evidence tables directly. PostgreSQL `AFTER` triggers transactionally
copy the minimum scheduling state into platform-owned rollup tables. The job rollup contains tenant and
job keys, status, accelerator class, queue timestamp, lease expiry, and update timestamp. The worker
rollup contains tenant and worker keys, CPU/CUDA booleans, GPU count, and last-seen time. Internal keys
make inserts, updates, deletes, and migration backfills exact, but are not selected into the API model.

The rollups deliberately exclude suite paths, agent or model versions, labels, worker capabilities,
hostnames, GPU names and UUIDs, telemetry, prompts, trajectories, artifacts, and guardrail evidence.
Integration tests seed distinctive sensitive values and prove they are absent from serialized reports.
Tenant `read`, `write`, and `admin` scopes receive HTTP 403 from the fleet endpoint.

## Consistency And Trust

Rollup changes commit in the same transaction as each source job or worker change. Lease activity and
worker activity are evaluated against PostgreSQL `now()` when the report is read, so expired leases and
stale workers disappear without a background reconciler. Startup rebuilds both rollups while tenant RLS
is temporarily unforced inside the advisory-locked schema migration transaction, then reinstalls forced
RLS and the synchronization triggers.

Static-config tenants that have workload rows but no lifecycle registry entry appear as `unregistered`.
Registered tenants appear even when they have no workload. Totals are sums of the per-tenant values;
the oldest queue age is the maximum tenant age.

This is an application-level disclosure boundary, not protection from the PostgreSQL owner. The schema
owner and database administrators can query rollup keys, alter trigger functions, or access source
tables and remain trusted. Do not expose the database credential to platform API callers. Keep the
`operator` credential static and narrowly held because tenant IDs, display names, lifecycle state,
resource pressure, and quota policy are still operationally sensitive.
