# Retention-Locked Evidence Checkpoints

Schema v16 closes the append-only ledger's database-administrator gap with signed external
checkpoints. A checkpoint binds the tenant, ledger sequence, entry count, head SHA-256, creation time,
and retention deadline in a canonical payload. AgentEval signs that payload with the active Ed25519
artifact key and stores the envelope in a forced-RLS, append-only PostgreSQL table before publication.

Checkpoints require Ed25519. HMAC does not provide independent public verification, and a public-only
auditor cannot create a checkpoint.

## S3 Object Lock

Configure an S3 bucket with Object Lock enabled at creation time and give the API permission for
`s3:GetBucketObjectLockConfiguration`, `s3:PutObject`, `s3:GetObject`, and
`s3:GetObjectRetention` on the checkpoint prefix.
Standard boto3 credential precedence supports workload identity, instance roles, web identity, and
the usual AWS environment variables; AgentEval adds no credential fields of its own.

```bash
export AECONTROL_CHECKPOINT_S3_BUCKET=agent-eval-evidence
export AECONTROL_CHECKPOINT_S3_REGION=us-east-1
export AECONTROL_CHECKPOINT_S3_PREFIX=control-plane/checkpoints

curl -X POST http://127.0.0.1:8000/api/v1/integrity/checkpoints \
  -H "Authorization: Bearer $AECONTROL_TENANT_ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"retention_days":90}'
```

Publication refuses buckets without Object Lock and sends `ObjectLockMode=COMPLIANCE`, the signed
retention deadline, a SHA-256 checksum, and `If-None-Match: *`. Object names are deterministic:

```text
<prefix>/<tenant>/<20-digit-sequence>-<ledger-head-sha256>-<checkpoint-uuid>.json
```

Every successful upload, including an idempotent retry, is read back through `GetObject`. AgentEval
requires byte equality with the canonical signed envelope, matching SHA-256 metadata,
`COMPLIANCE` mode, and an observed retention deadline at least as long as the signed policy. The
publication receipt records the destination, region, ETag, version ID, digest, retention deadline,
and verification time. It never treats a `PutObject` response alone as durable evidence.

Retries within five minutes reuse the same persisted envelope and are byte-idempotent. If the key
already exists, AgentEval verifies the retained copy; it never overwrites an object. An existing
object with different bytes fails publication. A later request can renew an unchanged ledger head
with a new checkpoint UUID and retention deadline, so an idle ledger never becomes impossible to
re-anchor.

## Independent Replication

Set a second destination to publish the same signed bytes independently to another region or cloud
account:

```bash
export AECONTROL_CHECKPOINT_REPLICA_S3_BUCKET=agent-eval-evidence-replica
export AECONTROL_CHECKPOINT_REPLICA_S3_REGION=us-west-2
export AECONTROL_CHECKPOINT_REPLICA_S3_PREFIX=control-plane/checkpoints
export AECONTROL_CHECKPOINT_REQUIRED_COPIES=2
```

Both destinations have independent Object Lock preflight, create-only upload, read-back, digest, and
retention verification. The default policy requires both configured copies. If one destination
succeeds and the other fails, publication returns an error without deleting the immutable success;
the next attempt verifies that existing copy and retries the missing destination. Error text contains
only logical destination IDs.

`AECONTROL_CHECKPOINT_REQUIRED_COPIES=1` explicitly allows degraded one-of-two completion and records
the failed destination in the receipt. This setting is intended for availability-sensitive policies;
it does not prove cross-region durability. Keep the production value at `2` when independent
retention is the control being asserted.

## Local Demonstration

The CLI provides a create-only filesystem sink for offline review and demonstrations:

```bash
uv run aecontrol store checkpoint --output checkpoints --retention-days 90
uv run aecontrol store checkpoint --s3 --retention-days 90
```

Files are created with exclusive-create semantics, flushed with `fsync`, and made read-only. A retry
accepts identical bytes and rejects different bytes at the same deterministic path. This protects
against accidental overwrite but is not independent retention: a host administrator can still change
or remove local files. S3 compliance mode is the production boundary implemented here.

## Audit And Rollback Detection

```bash
uv run aecontrol store verify
curl http://127.0.0.1:8000/api/v1/integrity
```

The ordinary integrity audit verifies every persisted checkpoint's canonical digest, Ed25519
signature, column envelope, anchored ledger sequence, and head hash. If an administrator disables the
ledger trigger and truncates the tail, a checkpoint reports `missing_sequence`; replacing an anchored
entry reports `head_mismatch`. The API and CLI return structured checkpoint failures and the CLI exits
nonzero.

`GET /api/v1/integrity/checkpoints` returns tenant-local signed envelopes for independent auditors.
The sync and async SDKs expose `publish_ledger_checkpoint` and `ledger_checkpoints`.

## Operational Boundaries

Checkpoint creation and its PostgreSQL insert are transactional with a tenant-local ledger advisory
lock, so the signed head cannot move during capture. S3 publication follows that commit. A failed
upload leaves a valid unpublished checkpoint; retrying the same ledger head returns the same envelope
and object key.

The feature does not create or configure buckets, IAM roles, lifecycle rules, provider-native
replication, or legal holds. Application-level dual publication proves two independently verified
copies, but operators must still alert on failures, protect the Ed25519 private key, independently
retain public keys, and choose a retention period consistent with policy. Direct cloud KMS/HSM
signing remains a separate hardening stage. Vault Transit remote Ed25519 signing is available through
[`vault-transit-signing.md`](vault-transit-signing.md).

The `checkpoint-replication` Kubernetes overlay runs a daily publisher at 03:30 UTC with
`concurrencyPolicy: Forbid`, bounded retries and runtime, two-copy enforcement, and a hardened
read-only container. Before applying it, replace both bucket names, regions, and the ServiceAccount
workload-identity annotation. Grant that identity only prefix-scoped write/read-back and retention
inspection in each independently administered bucket account.

```bash
kubectl apply -k deploy/overlays/checkpoint-replication
kubectl -n aecontrol create job --from=cronjob/aecontrol-checkpoint-publisher \
  aecontrol-checkpoint-publisher-smoke
kubectl -n aecontrol logs -f job/aecontrol-checkpoint-publisher-smoke
```

The overlay demonstrates the existing local Ed25519 Secret contract. Environments using Vault
Transit should patch the CronJob with the same token-file and public-key settings as the
`vault-transit` overlay while deleting local private-key injection. The command requires exactly one
of `--output` or `--s3` and exits nonzero on signing, configuration, retention, replication-policy,
or read-back failure.
