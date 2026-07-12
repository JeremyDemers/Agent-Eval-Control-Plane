# Operations

AgentEval exposes three local operational surfaces backed by PostgreSQL.

- `/healthz` verifies database connectivity and schema compatibility.
- `/readyz` returns `503` when work is queued but no worker has heartbeated in the last two minutes.
- `/metrics` emits Prometheus text with bounded labels for job states and gate outcomes.

The metrics include persisted run and comparison totals, jobs by lifecycle state, gate outcomes,
registered and active workers, expired leases, oldest queued-job age, and average completed-job
latency. Metric labels are fixed enums; run IDs, case IDs, model names, and worker IDs are deliberately
excluded to prevent cardinality growth.

Every HTTP response includes `X-Request-ID` and `Server-Timing`. A caller-supplied request ID is
preserved when it contains at most 64 alphanumeric, dot, underscore, or hyphen characters; otherwise
the service generates a UUID. Structured request logs include that ID, method, path, status, and
duration for correlation without recording request bodies or model prompts.

```bash
curl -i http://127.0.0.1:8000/readyz
curl -H 'X-Request-ID: release-check-42' http://127.0.0.1:8000/api/v1/operations
curl http://127.0.0.1:8000/metrics
```

These endpoints assume the same trusted local network boundary as the API. Production deployment
must place authentication, TLS, and scrape authorization in front of the service.
