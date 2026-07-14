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
caps work per checkpoint; raise it deliberately up to 1,000,000 for larger tenants. Checkpoint files
are limited to 1 MiB and must be regular non-symlink files.

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

## Trust Boundary

The verifier detects incomplete recovery, rollback behind a signed head, ledger mutation, source
deletion, payload drift, envelope drift, and unavailable or invalid verification keys. Forced RLS
continues to isolate tenants; each checkpoint selects only its signed tenant context.

The database role and PostgreSQL server remain trusted. A database administrator can replace both
data and runtime behavior, and the verifier does not prove that an object-store backup is available in
another region. Scheduled creation and cleanup of isolated restore clusters, cross-region promotion,
and external archival of drill reports remain operational roadmap items.
