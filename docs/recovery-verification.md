# Recovery Verification

Starting PostgreSQL is not proof that a recovery is usable or trustworthy. AgentEval verifies an
isolated recovery against an Ed25519-signed ledger checkpoint that was exported to create-only or
Object-Locked storage before the selected recovery target.

The verifier never initializes or migrates the database. Its first PostgreSQL statement makes the
transaction read-only, and the report confirms that state. It then checks:

- the restored schema is exactly the application-supported version;
- PostgreSQL has completed recovery and promoted the candidate primary;
- every supplied checkpoint is fresh, structurally valid, and signed by a configured public key;
- the checkpoint persisted in PostgreSQL exactly matches the external immutable envelope;
- every tenant ledger sequence, previous hash, entry hash, and final head through the checkpoint;
- every referenced source artifact's canonical digest, signature envelope, and signature.

Reports contain identifiers, counts, bounded failure codes, and timestamps. They never contain
artifact payloads, signing keys, or database credentials.

## Capture A Recovery Anchor

Create one checkpoint for each tenant whose recovery objective is being tested. The checkpoint must
commit before the selected PITR target, and its external publication must complete before the drill:

```bash
export AECONTROL_TENANT_ID=research
uv run aecontrol store checkpoint --s3 --retention-days 90 --json
```

The S3 sink requires Object Lock `COMPLIANCE` mode and conditional create semantics. See
[`evidence-checkpoints.md`](evidence-checkpoints.md) for bucket and key policy. A target older than the
checkpoint cannot prove that checkpoint and should fail with `checkpoint_missing`.

## Verify An Isolated Restore

Follow the CloudNativePG recovery procedure in [`database.md`](database.md). Configure only public
verification keys in the verifier environment; private signing material and Vault credentials are
not required:

```bash
export DATABASE_URL='postgresql://.../aecontrol'
export AECONTROL_ARTIFACT_ED25519_PUBLIC_KEYS='{"evidence-v1":"BASE64_PUBLIC_KEY"}'
uv run aecontrol store verify-recovery \
  --checkpoint /secure/checkpoints/research.json \
  --checkpoint /secure/checkpoints/safety.json \
  --max-checkpoint-age-hours 48 \
  --json
```

The command exits zero only when every check passes. `--max-ledger-entries` defaults to 100,000 and
caps work per checkpoint; raise it deliberately up to 1,000,000 for larger tenants. At most 16
checkpoint envelopes are accepted. Files are limited to 1 MiB and must be regular non-symlink files.
The report preserves the exact failure count but includes no more than 20 failure details per
checkpoint, preventing corrupted data from producing unbounded evidence or logs.

For Kubernetes, copy the excluded
`deploy/overlays/cloudnative-pg-pitr/recovery-verification-job.example.yaml`. Create
`aecontrol-recovery-verifier` from the public-key JSON and `aecontrol-recovery-checkpoint` from the
immutable envelope, then apply the Job only after the restore Cluster reports `Ready`:

```bash
kubectl -n aecontrol create secret generic aecontrol-recovery-verifier \
  --from-literal=ed25519-public-keys='{"evidence-v1":"BASE64_PUBLIC_KEY"}'
kubectl -n aecontrol create secret generic aecontrol-recovery-checkpoint \
  --from-file=checkpoint.json=/secure/checkpoints/research.json
kubectl apply -f /tmp/aecontrol-recovery-verification.yaml
kubectl -n aecontrol wait --for=condition=Complete \
  job/aecontrol-recovery-verification --timeout=30m
kubectl -n aecontrol logs job/aecontrol-recovery-verification
```

Use an external secret manager in production instead of imperative Secret creation. Keep the Job log
with the backup ID, recovery target, CloudNativePG Cluster status, and incident or drill record.

## Scheduled Drills

The `cloudnative-pg-recovery-drill` overlay runs at 04:00 UTC each Sunday. Its project-owned Python
orchestrator uses the in-cluster HTTPS API directly; no shell or `kubectl` utility image is involved.
The namespaced Role can only create, read, list, and delete CloudNativePG `Cluster` resources and
Kubernetes `Job` resources.

Each run performs the following state machine:

1. Prune the oldest retained failed candidate so no more than two can remain after this run.
2. Bootstrap a single-instance candidate from the latest base backup and archived WAL.
3. Wait for the CloudNativePG `Ready` condition, then create a public-key-only verifier Job.
4. Publish the canonical JSON report to S3 with conditional create, SHA-256 metadata, and Object Lock
   `COMPLIANCE` retention.
5. Delete the successful verifier Job and restored Cluster. Preserve both on failure for diagnosis.

The checkpoint Secret is an explicit prerequisite. Do not create a new checkpoint immediately before
a drill: its transaction may not yet be present in archived WAL. Instead, update the Secret from the
normal immutable checkpoint-publication pipeline after confirming the checkpoint predates the
recovery point. The default seven-day freshness window matches the weekly schedule.

Create the three excluded Secrets from the examples, preferably through the external secret manager,
then apply the overlay:

```bash
kubectl apply -k deploy/overlays/cloudnative-pg-recovery-drill
kubectl -n aecontrol create job --from=cronjob/aecontrol-recovery-drill \
  aecontrol-recovery-drill-manual
kubectl -n aecontrol logs -f job/aecontrol-recovery-drill-manual
```

`aecontrol-recovery-checkpoints` may contain one `*.json` key per tenant, up to 16.
`aecontrol-recovery-verifier` contains only the Ed25519 public-key map.
`aecontrol-recovery-report-s3` identifies an Object-Locked bucket and report-writer credentials. The
writer needs `s3:GetObjectLockConfiguration`, `s3:PutObject`, and `s3:GetObject` for the report prefix,
without delete or retention-bypass permissions.

## Trust Boundary

The verifier detects incomplete recovery, rollback behind a signed head, ledger mutation, source
deletion, payload drift, envelope drift, and unavailable or invalid verification keys. Forced RLS
continues to isolate tenants; each checkpoint selects only its signed tenant context.

The database role, Kubernetes control plane, CloudNativePG operator, and PostgreSQL server remain
trusted. A database administrator can replace both data and runtime behavior. A cluster administrator
can alter the CronJob, RBAC, Secrets, or workload image. The drill proves recovery from the configured
object store; it does not prove that the archive is independently available in another region.
Cross-region archive replication and promotion remain operational roadmap items.
