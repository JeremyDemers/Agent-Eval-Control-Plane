# API Authentication

AgentEval supports optional scoped bearer keys for `/api/v1` endpoints. Authentication is disabled
for the zero-configuration local demo and enabled when `AECONTROL_AUTH_CONFIG` points to a YAML file.
Health, readiness, API documentation, and the local browser explorer remain public so operators can
diagnose the service and inspect the portfolio demo.

## Create a key

Generate a high-entropy secret with your preferred secret manager, then hash it without placing the
plaintext value in the configuration:

```bash
uv run aecontrol auth hash-key
```

Create `auth.yaml` with the printed SHA-256 digest:

```yaml
keys:
  - key_id: automation
    secret_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    scopes: [read, write]
  - key_id: auditor
    secret_sha256: abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    scopes: [read]
```

Validate and start the service:

```bash
uv run aecontrol auth validate auth.yaml
AECONTROL_AUTH_CONFIG=auth.yaml make serve
curl -H "Authorization: Bearer $AECONTROL_API_KEY" http://127.0.0.1:8000/api/v1/runs
```

The typed synchronous and asynchronous SDK clients accept `api_key=` and also read
`AECONTROL_API_KEY`, allowing the plaintext credential to remain in the deployment secret provider.

`read` permits API queries, `write` permits evaluation, queue, cancellation, and comparison
operations, and `admin` satisfies every scope. Keys should be random and rotated through the
deployment secret manager; the service stores only their digests in memory and never logs bearer
credentials.
