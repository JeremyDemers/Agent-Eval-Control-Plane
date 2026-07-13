# Production PostgreSQL

AgentEval accepts any libpq-compatible `DATABASE_URL`, including managed PostgreSQL endpoints and TLS
parameters. Keep credentials in a secret manager and require certificate verification where the
provider supports it:

```text
postgresql://aecontrol:REDACTED@db.example:5432/aecontrol?sslmode=verify-full&sslrootcert=/etc/ssl/provider-ca.pem
```

## Connection Modes

Direct connections remain the default and are appropriate for local commands or deployments already
fronted by PgBouncer. Long-lived API and worker processes can enable Psycopg's thread-safe bounded
pool through environment variables:

```bash
export AECONTROL_DATABASE_POOL_MIN_SIZE=1
export AECONTROL_DATABASE_POOL_MAX_SIZE=8
export AECONTROL_DATABASE_POOL_TIMEOUT_SECONDS=5
export AECONTROL_DATABASE_POOL_MAX_WAITING=20
```

Setting the maximum to `0` disables the in-process pool. When enabled, startup explicitly opens the
pool, waits for its minimum connections, and fails if connectivity is unavailable before the timeout.
Connections are checked before checkout, transactions commit or roll back before return, and API and
worker shutdown closes background pool resources. `aecontrol doctor` reports mode and safe bounds
without exposing the database URL.

Size the pool across replicas, not per process in isolation. Two API replicas at maximum `8`, three
workers at maximum `4`, and administrative headroom require at least 28 server connections. Prefer a
small bound backed by observed waiting-request metrics over matching the number of application
threads.

## Schema Coordination

Every schema initialization transaction takes an exclusive PostgreSQL advisory lock derived from the
schema name before running idempotent DDL. This serializes AgentEval replicas during rolling startup
and automatically releases the lock on commit, rollback, or connection loss.

```bash
export AECONTROL_DATABASE_MIGRATION_LOCK_TIMEOUT_SECONDS=30
```

The transaction-local PostgreSQL `lock_timeout` prevents a replica from waiting forever. A timed-out
initializer fails startup instead of serving against a partially upgraded schema. The advisory lock
coordinates AgentEval processes that follow this contract; external DDL tools must still be scheduled
and controlled by the operator.

## Monitoring

When pooling is active, `/metrics` exports:

- `aecontrol_database_pool_connections{state="size|available"}`
- `aecontrol_database_pool_limit{bound="minimum|maximum"}`
- `aecontrol_database_pool_waiting_requests`

Alert on sustained waiting requests and pool exhaustion, then inspect query latency and transaction
duration before increasing connection limits. The development PostgreSQL StatefulSet remains a local
portfolio fixture; production provisioning, backup, failover, and maintenance belong to a managed
service or PostgreSQL operator.
