# Artifact Integrity and Authenticity

AgentEval stores complete evaluation runs, release comparisons, and NeMo Guardrails checks as
PostgreSQL JSONB evidence. SHA-256 digests use recursively sorted canonical JSON, normalized signed
zero, compact separators, ASCII escaping, and rejection of non-finite numbers.

Schema v13 stores a versioned signature envelope containing algorithm, key ID, and signature. Ed25519
is the preferred mode: API and worker processes sign with an external private key, while audit-only
processes verify with the public key and have no authority to create evidence. PostgreSQL stores only
the envelope and never stores configured key material. Existing HMAC-SHA256 rows are migrated into
the envelope without being resigned, and the legacy HMAC environment remains supported.

## Ed25519 Setup

Generate a raw 32-byte Ed25519 private seed and its 32-byte public key:

```bash
KEY_ID=portfolio-2026-07
KEY_PAIR="$(uv run aecontrol store generate-signing-key --algorithm ed25519)"
export AECONTROL_ARTIFACT_SIGNING_KEY_ID="$KEY_ID"
export AECONTROL_ARTIFACT_SIGNING_ALGORITHM=ed25519
export AECONTROL_ARTIFACT_ED25519_PRIVATE_KEYS="$(
  jq -c --arg id "$KEY_ID" '{($id): .private_key}' <<<"$KEY_PAIR"
)"
export AECONTROL_ARTIFACT_ED25519_PUBLIC_KEYS="$(
  jq -c --arg id "$KEY_ID" '{($id): .public_key}' <<<"$KEY_PAIR"
)"
```

Invalid base64, key lengths, IDs, algorithms, and mismatched private/public pairs stop startup. New
writes persist payload, digest, and signature envelope in one transaction. Reads recompute the digest,
verify the envelope, and only then perform Pydantic validation. A mismatch, missing historical key,
or incomplete envelope returns HTTP 409 without returning or rendering the untrusted payload.

## Public-Only Audit

An independent audit process needs only `AECONTROL_ARTIFACT_ED25519_PUBLIC_KEYS`. Leave the active key
ID, algorithm, and private map unset. It can run verification but cannot sign a new artifact:

```bash
unset AECONTROL_ARTIFACT_SIGNING_KEY_ID
unset AECONTROL_ARTIFACT_SIGNING_ALGORITHM
unset AECONTROL_ARTIFACT_ED25519_PRIVATE_KEYS
export AECONTROL_ARTIFACT_ED25519_PUBLIC_KEYS='{"portfolio-2026-07":"base64-public-key"}'
uv run aecontrol store verify
curl http://127.0.0.1:8000/api/v1/integrity
```

The audit reports checked, valid, signed, unsigned, and per-algorithm counts. Failures identify digest
mismatch, signature mismatch, or unavailable verification keys and include artifact type, UUID,
algorithm, key ID, and digests, but never artifact payloads or private material.

The same command verifies the schema v14 append-only evidence chain and exits nonzero for artifact or
ledger failures. See [`evidence-transparency.md`](evidence-transparency.md) for ledger guarantees and
external checkpoint requirements.

Schema v16 checkpoints require an active Ed25519 private key and publish public-verifiable ledger
heads to create-only filesystem or S3 Object Lock sinks. See
[`evidence-checkpoints.md`](evidence-checkpoints.md).

The active private key can instead remain inside Vault Transit. AgentEval pins the Vault key version,
stores the same base64 Ed25519 envelope, and continues to verify locally using public keys. See
[`vault-transit-signing.md`](vault-transit-signing.md).

AWS KMS can retain the same key material behind an immutable key ARN and short-lived workload
credentials. AgentEval fixes `ED25519_SHA_512` with raw-message signing, checks response identity and
shape, and verifies each result locally before commit. See [`aws-kms-signing.md`](aws-kms-signing.md).

## Rotation and HMAC Compatibility

1. Retain every public key referenced by stored Ed25519 evidence.
2. Add a new private/public pair, change the active key ID, and restart all signing processes.
3. Confirm `aecontrol store verify` reports every artifact valid before removing an old private key.
4. Keep old public keys available for the entire evidence-retention window.

Removing a public key does not rewrite evidence. Reads of artifacts signed by that key fail closed and
the audit reports `missing_signing_key`, making early retirement immediately visible.

Legacy deployments may continue using `AECONTROL_ARTIFACT_SIGNING_KEYS` with
`AECONTROL_ARTIFACT_SIGNING_KEY_ID`; the algorithm defaults to `hmac-sha256`. During migration, load
the old HMAC map alongside the Ed25519 maps, set the active algorithm to `ed25519`, and use the audit's
per-algorithm counts to track historical HMAC evidence.

## Threat Model

Canonical SHA-256 detects accidental changes. Domain-separated signatures bind AgentEval's format
version, artifact type, UUID, and digest, preventing a valid signature from being copied to another
record. Ed25519 lets auditors verify with non-secret material and prevents a compromised audit process
or PostgreSQL writer from forging evidence.

An attacker who compromises an active local private key can still forge signatures. Vault Transit
and AWS KMS remove that key from AgentEval, but a compromised authorized workload can request
signatures until its token or role is revoked. Database rows are not retention locked. Export signed
envelopes to independently administered, versioned, retention-locked object storage.
