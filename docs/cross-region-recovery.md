# Cross-Region PostgreSQL Recovery

The distributed CloudNativePG deployment is an operator-controlled disaster-recovery path, not an
automatic multi-writer database. `aecontrol-postgres` begins as the global primary and
`aecontrol-postgres-secondary` continuously replays its archived WAL in a separate Kubernetes
cluster. Only the global primary may receive application writes.

## Topology and Recovery Objectives

Deploy `deploy/overlays/cloudnative-pg-distributed` only in the secondary Kubernetes cluster. It
creates a three-instance replica, definitions for both regional archives, and promotion RBAC. Apply
the excluded `primary-topology-patch.example.yaml` to the primary Cluster through the primary
region's reviewed GitOps path. Both Cluster resources must list both members of the distributed
topology.

The primary region already uses `aecontrol-postgres-backup` as its local archive. Before applying the
topology patch there, also install an environment-owned copy of `secondary-archive.yaml` so the
former primary can read the secondary archive after switchover. The secondary overlay uses its own
local aliases for both archives; ObjectStore names need not match across Kubernetes clusters.

Before applying the secondary overlay, provision both archive credential Secrets and
`aecontrol-postgres-app-credentials` from the external secret manager. The latter must contain the
same `username` and `password` values in both regions. Do not apply the placeholder example.

Replace both example S3 destinations and credentials before deployment. The active archive in each
region must be reachable from the other region and must use a dedicated bucket or prefix. Enable
versioning, Object Lock, encryption, replication alerts, and a separately administered immutable
replication destination. Do not replicate one region's objects over the other region's active
archive prefix. CloudNativePG reads the active source archive; the replicated immutable copy is the
independent recovery and forensic tier.

The achievable recovery point is bounded by the newest WAL durably available to the secondary.
Measure archive delay and cross-region object replication delay against an explicit RPO. Measure a
rehearsed promotion plus application routing against the RTO. A resource reporting `Ready` does not
prove either objective.

The following must also be identical in both regions:

- CloudNativePG operator major/minor version and PostgreSQL major version.
- Application role definitions and the externally managed `aecontrol-postgres-app-credentials`
  username/password values. Use the excluded example with an external secret manager in both
  regions; keep region-local connection URIs in separate application Secrets.
- Database schema compatibility and artifact-verification public keys.
- Network, DNS, and application-secret changes required to route to the regional `-rw` Service.

## Planned Switchover

Start with a successful base backup, a fresh signed ledger checkpoint, a successful recovery drill,
healthy WAL archiving, and zero object-replication backlog. Pause application writes or drain every
writer before changing the source. Retain the incident/change identifier with every command output.

1. In the primary region, atomically change the source Cluster to name the secondary as both
   `spec.replica.primary` and `spec.replica.source`. CloudNativePG fences the former primary, shuts
   PostgreSQL down, archives the shutdown checkpoint WAL, and publishes `status.demotionToken`.
2. Confirm the former primary is no longer accepting writes. Read the token into a protected file;
   do not put it in shell history, tickets, logs, or Git.

   ```bash
   umask 077
   kubectl --context primary -n aecontrol get cluster aecontrol-postgres \
     -o jsonpath='{.status.demotionToken}' > /tmp/aecontrol-promotion-token
   test -s /tmp/aecontrol-promotion-token
   ```

3. Transfer the file through the approved secret channel. In the secondary region, create the
   excluded Secret without printing the token and confirm the source and target operator versions
   match.

   ```bash
   kubectl --context secondary -n aecontrol create secret generic \
     aecontrol-postgres-promotion-token \
     --from-file=token=/tmp/aecontrol-promotion-token \
     --dry-run=client -o yaml | kubectl --context secondary apply -f -
   cp deploy/overlays/cloudnative-pg-distributed/promotion-job.example.yaml \
     /tmp/aecontrol-promotion-job.yaml
   # Replace REPLACE_WITH_OPERATOR_VERSION in the temporary Job.
   kubectl --context secondary -n aecontrol apply -f /tmp/aecontrol-promotion-job.yaml
   kubectl --context secondary -n aecontrol wait --for=condition=complete \
     job/aecontrol-postgres-promote-secondary --timeout=35m
   ```

The promotion command parses the bounded base64 JSON token, rejects duplicate or unexpected fields,
checks the operator-version policy, verifies the token system identifier against the target, and
requires a healthy target still following the expected source. It submits `primary`, `source`, and
`promotionToken` in one merge patch with the observed Kubernetes `resourceVersion`. CloudNativePG
then waits until the target has replayed through the token's REDO LSN. Completion requires a `Ready`
Cluster whose `status.lastPromotionToken` matches; output records only the token's SHA-256 digest.

4. Verify the secondary `-rw` Service with a read-only integrity audit before changing application
   routing. Resume writes only after the incident commander approves the cutover. Run a signed
   canary evaluation, publish a new ledger checkpoint, and verify new WAL in the secondary archive.
5. Delete the token Secret and protected local file after retaining the redacted Job output,
   Kubernetes audit event, checkpoint identifiers, archive timestamps, and object-replication
   inventory in the change record.

## Unplanned Failover

Do not invent a promotion token when the original primary cannot be safely demoted. A tokenless
CloudNativePG promotion is a failover with a data-loss boundary at the latest replayed WAL. It also
means the former primary cannot rejoin this topology and must be rebuilt from the new primary.
Require incident-command approval, prove the old write endpoint is fenced at the network and
application layers, record the observed replay position, and follow the CloudNativePG failover
procedure directly. The guarded `aecontrol promote-replica` command intentionally refuses this path.

## Reversal and Drills

After a controlled switchover, the former primary follows the new primary. Wait until it is caught up
and its local archive is healthy before reversing direction with the same two-phase procedure and a
new token. Never reuse a token.

Exercise the full workflow in non-production at least quarterly, including application routing and
the independent immutable archive copy. Production exercises may stop after source demotion and
controlled promotion only inside an approved maintenance window. Continue the weekly isolated
restore drill: replica availability and backup recoverability are different claims and require
different evidence.

## Trust Boundary

The guardrail cannot prove that the old primary was fenced outside Kubernetes, that DNS or clients
stopped writing, that S3 replication is complete, or that a cloud account is independently
administered. Kubernetes RBAC limits its service account to `get` and `patch` one named Cluster, but a
principal able to replace the Job, Secret, Role, or Cluster remains privileged. CloudNativePG and the
Barman Cloud plugin remain external operators whose versions, admission controls, and supply-chain
policy are owned by the platform team.
