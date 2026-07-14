# Evidence Transparency Ledger

Schema v14 records every evaluation run, comparison, and NeMo Guardrails check in a tenant-scoped
append-only PostgreSQL ledger. The ledger is written in the same transaction as the source artifact,
so an artifact cannot commit without its transparency entry.

Each entry commits to:

- Tenant ID and tenant-local sequence.
- Artifact type, UUID, and canonical payload SHA-256.
- Signature algorithm, key ID, and signature value.
- The previous ledger entry SHA-256.

The first entry references 64 zeroes. Subsequent entries form a deterministic SHA-256 chain. Entry
timestamps are operational metadata and are deliberately excluded from the hash so database timezone
normalization cannot change verification bytes.

## Concurrency And Isolation

Writers take a transaction-scoped PostgreSQL advisory lock derived from schema and tenant before
reading the current head and appending the next sequence. Different tenants can append concurrently;
writes inside one tenant serialize only for the short ledger operation. Forced row-level security
uses the same transaction-local tenant identity as source evidence.

The `(tenant_id, artifact_type, artifact_id)` uniqueness constraint makes retries idempotent. A retry
with the same envelope reuses the existing entry. A conflicting live write raises an error and rolls
back its source-row update in the same transaction.

## Verification

```bash
uv run aecontrol store verify
curl http://127.0.0.1:8000/api/v1/integrity
```

Verification checks tenant-local sequence continuity, previous-hash links, recomputed entry hashes,
and the source artifact's current digest and signature envelope. It reports ledger entries checked,
valid entries, the current head SHA-256, and structured failures for sequence gaps, broken links,
entry mutation, missing source artifacts, and source-envelope mismatch. The CLI exits nonzero for any
artifact or ledger failure.

A PostgreSQL trigger rejects every ledger `UPDATE` and `DELETE`, including accidental operator
commands. Dropping a source artifact does not erase its ledger entry and is reported as
`missing_artifact`.

## Migration

Existing artifacts are backfilled in tenant, event-time, type, and UUID order. Schema initialization
holds the migration advisory lock and PostgreSQL access-exclusive table locks while temporarily
removing `FORCE ROW LEVEL SECURITY` from the table owner. This permits one transaction to migrate all
tenants without exposing cross-tenant rows to concurrent application requests. Forced policies are
restored before commit.

Already-recorded entries are never rewritten during startup. If source evidence has changed, startup
completes and the audit reports the mismatch instead of silently accepting a new chain value.

## Trust Boundary

The chain detects interior deletion, reordering, source deletion, and mutation while normal database
controls remain active. It does not by itself make PostgreSQL retention locked. A database
administrator who can disable or drop the trigger could truncate the chain tail and present the new
last entry as the head.

Schema v16 implements Ed25519-signed checkpoints with create-only local export and S3 Object Lock
compliance retention. The ordinary audit compares every checkpoint sequence and head to the live
chain, detecting rollback and tail truncation. See
[`evidence-checkpoints.md`](evidence-checkpoints.md). AWS KMS can keep checkpoint signing keys outside
the workload through [`aws-kms-signing.md`](aws-kms-signing.md); independently administered
cross-region checkpoint replication is also available.
