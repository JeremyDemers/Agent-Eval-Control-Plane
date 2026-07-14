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

Schema v17 also uses tenant-specific transaction advisory locks for queue and execution quota
admission. Those locks are independent of the schema migration lock and serialize only submissions
and worker claims for the same tenant. See [`tenant-quotas.md`](tenant-quotas.md).

Schema v18 creates platform-owned fleet job and worker rollups outside tenant RLS. Source-table
triggers synchronize minimal scheduling fields in the same transaction, while startup rebuilds the
rollups under the migration lock. The operator report aggregates only these tables; see
[`fleet-analytics.md`](fleet-analytics.md) for the excluded fields and database-owner trust boundary.

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

High availability is not disaster recovery. The following backup overlay adds a recovery path, but
production still requires external secret management, bucket immutability, restore drills, alert
routing, and organization-specific recovery objectives.

## Object-Storage Backups

The `cloudnative-pg-pitr` overlay uses Barman Cloud's CNPG-I plugin rather than CloudNativePG's
deprecated in-tree object-store integration. It archives WAL continuously, requests gzip compression
and S3 AES256 server-side encryption, starts one backup immediately, schedules later base backups at
02:00 UTC each day, prefers a standby, and maintains a 30-day recovery window.

The plugin requires cert-manager and must run in the same namespace as the CloudNativePG operator.
Install the pinned plugin release after verifying both prerequisites:

```bash
cmctl check api
kubectl get deployment -n cnpg-system cnpg-controller-manager \
  -o jsonpath='{.spec.template.spec.containers[*].image}'
kubectl apply -f \
  https://github.com/cloudnative-pg/plugin-barman-cloud/releases/download/v0.13.0/manifest.yaml
kubectl rollout status deployment/barman-cloud -n cnpg-system --timeout=5m
```

Create the S3 credential Secret from an external secret manager. For an isolated test environment,
the excluded example documents the required keys:

```bash
cp deploy/overlays/cloudnative-pg-pitr/backup-secret.example.yaml \
  /tmp/aecontrol-backup-s3.yaml
# Replace both placeholders without committing the result.
kubectl apply -f /tmp/aecontrol-backup-s3.yaml
```

Before applying the overlay, replace `s3://replace-with-backup-bucket/aecontrol` in
`object-store.yaml` through an environment-owned Kustomize patch. Use a dedicated bucket or prefix,
enable bucket versioning and object lock, and apply lifecycle expiration after the 30-day Barman
window. Prefer workload identity such as EKS IRSA over long-lived access keys where the provider
supports it.

```bash
kubectl apply -k deploy/overlays/cloudnative-pg-pitr
kubectl -n aecontrol get scheduledbackup,backup
kubectl -n aecontrol get objectstore aecontrol-postgres-backup -o yaml
```

Do not call the backup system healthy merely because the resources exist. Wait for a `Backup` with a
`completed` phase, confirm `status.serverRecoveryWindow` has a first recoverability point and latest
successful backup, and verify archived objects from the storage provider. The optional
`cloudnative-pg-pitr-monitoring` overlay includes the database PodMonitor plus critical alerts when
the latest backup failed, the success metric is absent for one hour, or the latest successful base
backup is more than 25 hours old.

## Point-in-Time Recovery Drill

Recovery creates a new cluster; it never overwrites the source cluster in place. Record the intended
UTC recovery timestamp from incident evidence, confirm it falls within the reported recovery window,
and create an isolated manifest from the excluded template:

```bash
cp deploy/overlays/cloudnative-pg-pitr/restore.example.yaml \
  /tmp/aecontrol-postgres-restore.yaml
# Replace REPLACE_WITH_RFC3339_TIMESTAMP, for example 2026-07-13T18:42:00Z.
kubectl apply -f /tmp/aecontrol-postgres-restore.yaml
kubectl -n aecontrol wait --for=condition=Ready cluster/aecontrol-postgres-restore \
  --timeout=30m
kubectl -n aecontrol get pods,pvc -l cnpg.io/cluster=aecontrol-postgres-restore
```

The restore template reads from the original `aecontrol-postgres` archive but does not enable WAL
archiving for the candidate. CloudNativePG generates fresh connection credentials in
`aecontrol-postgres-restore-app`; the original Kubernetes Secrets are not part of the physical
database backup and must be recoverable from the external secret manager.

Validate schema version, row counts, integrity signatures, representative run evidence, and the
chosen stopping point against the isolated read-write service. Keep application deployments pointed
at the original Secret until an incident commander approves a reviewed Kustomize cutover to the
restore Secret's `uri` key. Preserve the failed cluster and archive, then configure a new write
destination before enabling backups on the promoted cluster. Removing `recoveryTarget` from a copy
of the template performs recovery through the latest available WAL instead of timestamp-based PITR.
