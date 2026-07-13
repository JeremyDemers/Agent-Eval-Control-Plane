# Artifact Integrity and Authenticity

AgentEval stores complete evaluation runs, release comparisons, and NeMo Guardrails checks as
PostgreSQL JSONB evidence. SHA-256 digests use recursively sorted canonical JSON,
normalized signed zero, compact separators, ASCII escaping, and rejection of non-finite numbers.

An optional external HMAC-SHA256 keyring authenticates each digest together with its artifact type
and UUID. The active key signs new writes; retained historical keys verify evidence created before a
rotation. PostgreSQL stores only the key ID and signature, never the key material.

Generate and configure a 256-bit key before starting the API or workers:

```bash
AECONTROL_ARTIFACT_SIGNING_KEY_ID=portfolio-2026-07
AECONTROL_ARTIFACT_SIGNING_KEYS="{\"portfolio-2026-07\":\"$(uv run aecontrol store generate-signing-key)\"}"
export AECONTROL_ARTIFACT_SIGNING_KEY_ID AECONTROL_ARTIFACT_SIGNING_KEYS
```

Both variables must be set together. The keyring must be a non-empty JSON object whose values are
base64-encoded keys of at least 32 bytes. Invalid configuration stops the process instead of silently
disabling signing.

New writes persist payload, digest, key ID, and signature in one transaction. Full artifact reads
recompute the digest, verify any signature, and only then perform Pydantic validation. A mismatch,
missing historical key, or incomplete signature returns HTTP 409; the untrusted payload is not
rendered or returned. Summary and queue records remain available for incident diagnosis.

```bash
uv run aecontrol store verify
curl http://127.0.0.1:8000/api/v1/integrity
```

The audit reports checked, valid, signed, and unsigned counts. Failures identify digest mismatch,
signature mismatch, or unavailable signing key and include the artifact type, UUID, and digests, but
never artifact payloads or key material. Schema v7 upgrades older databases in place and leaves
existing evidence unsigned and readable so operators can distinguish migration history from faults.

## Key Rotation

1. Add the new base64 key to `AECONTROL_ARTIFACT_SIGNING_KEYS` while retaining every key ID referenced
   by existing signed evidence.
2. Set `AECONTROL_ARTIFACT_SIGNING_KEY_ID` to the new ID and restart all API and worker processes with
   the same keyring.
3. Confirm `uv run aecontrol store verify` reports every artifact valid before retiring an old key.

Removing a key does not rewrite evidence. Reads of artifacts signed by that key fail closed and the
audit reports `missing_signing_key`. This makes accidental early retirement immediately visible.

## Threat Model

Canonical SHA-256 detects accidental changes. HMAC additionally protects against an attacker who can
write PostgreSQL payloads and digests but cannot access the external keyring. Domain separation binds
the signature to AgentEval's format version, artifact type, UUID, and digest, preventing a valid
signature from being copied to another record type or identity.

HMAC is shared-key authentication, not a public-key digital signature: any process with a signing key
can create valid signatures, so it does not provide nonrepudiation. An attacker who compromises an
API or worker process, Kubernetes Secret, or external secret manager can forge evidence. PostgreSQL
rows are also not immutable. Production systems requiring independent attestation should use a KMS
or asymmetric signing service and export retention-locked copies to immutable object storage.
