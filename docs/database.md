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
duration before increasing connection limits.

## CloudNativePG Production Overlay

The Kubernetes base retains a single-node PostgreSQL StatefulSet for local and portfolio clusters.
The `cloudnative-pg` overlay removes that StatefulSet and Service, provisions a three-instance
PostgreSQL 17 cluster, and points every AgentEval deployment at the operator-generated
`aecontrol-postgres-app` Secret's `uri` key. CloudNativePG owns database credentials, primary routing,
replication, and rolling switchover; the existing `aecontrol-database` Secret remains the source for
the NVIDIA API key and artifact-signing keyring.

Install the pinned CloudNativePG operator before applying the overlay:

```bash
kubectl apply --server-side \
  -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.29/releases/cnpg-1.29.2.yaml
kubectl rollout status deployment/cnpg-controller-manager -n cnpg-system --timeout=5m

kubectl apply -f /tmp/aecontrol-secret.yaml
kubectl apply -k deploy/overlays/cloudnative-pg
kubectl -n aecontrol wait --for=condition=Ready cluster/aecontrol-postgres --timeout=10m
kubectl -n aecontrol rollout status deployment/api --timeout=5m
kubectl -n aecontrol get cluster,pods,pvc
```

Required pod anti-affinity places the primary and two replicas on different Kubernetes nodes. The
cluster therefore needs at least three schedulable nodes and a storage class able to provision six
ReadWriteOnce volumes: one 20 GiB data volume and one 5 GiB WAL volume per instance. Set
`storage.storageClass` and `walStorage.storageClass` in an environment patch when the default storage
class is unsuitable. Resize storage declaratively after confirming the storage class supports volume
expansion; persistent volumes cannot be shrunk in place.

The cluster uses `ANY 1` synchronous replication with required data durability and failover quorum.
Each acknowledged commit has reached at least one standby. If the primary fails while only one
standby remains reachable, automatic failover is intentionally blocked because the operator cannot
prove that the remaining replica contains every acknowledged transaction. This favors consistency
over write availability during a second failure or network partition. Operators should investigate
node and network health instead of forcing promotion without reconciling the data-loss risk.

CloudNativePG metrics can be exposed to Prometheus Operator explicitly:

```bash
kubectl apply -k deploy/overlays/cloudnative-pg-monitoring
kubectl -n aecontrol get podmonitor aecontrol-postgres
```

The monitoring overlay requires the `monitoring.coreos.com/v1` PodMonitor CRD. The database image is
pinned to the PostgreSQL 17 standard track; production promotion should resolve and approve an image
digest under the organization's patching policy.

High availability is not disaster recovery. This overlay does not yet configure object-storage
backups, retention, restore testing, or point-in-time recovery. Those controls are required before a
production launch, along with external secret management, encryption policy, alerting, and a tested
failure-and-restore runbook.
