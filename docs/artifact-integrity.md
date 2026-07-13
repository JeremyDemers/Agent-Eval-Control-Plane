# Artifact Integrity

AgentEval stores complete evaluation runs, release comparisons, and NeMo Guardrails checks as
PostgreSQL JSONB evidence. SHA-256 digests use recursively sorted canonical JSON,
normalized signed zero, compact separators, ASCII escaping, and rejection of non-finite numbers.

New writes persist the payload and digest in one transaction. Full artifact reads recompute and
compare the digest before Pydantic validation; a mismatch returns HTTP 409 and the untrusted payload
is not rendered or returned. Summary and queue records remain available for incident diagnosis.

```bash
uv run aecontrol store verify
curl http://127.0.0.1:8000/api/v1/integrity
```

The audit reports checked and valid counts plus artifact type, ID, stored digest, and computed digest
for failures. It never returns artifact payloads. Schema-v1 and schema-v2 databases are upgraded in
place: missing run and comparison digests are calculated from the stored JSONB representation before
the columns become non-null. Schema v5 adds indexed Guardrails evidence to the same audit contract.

SHA-256 provides tamper evidence against accidental changes and database writes outside the control
plane. It is not a digital signature and does not protect against an attacker who can modify both the
payload and digest. Production deployments that require non-repudiation should sign digests with a
key held outside PostgreSQL and export immutable copies to object storage.
