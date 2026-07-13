# NeMo Guardrails Evidence

AgentEval can validate an input or an existing input/output pair through the NVIDIA NeMo Guardrails
API server. It requests input and output rails only, disables dialog and retrieval generation, and asks
the server to return activated-rail and timing statistics.

```bash
export NEMO_GUARDRAILS_BASE_URL=http://127.0.0.1:8000/v1
uv run aecontrol guardrails configs
uv run aecontrol guardrails check \
  --model meta/llama-3.1-8b-instruct \
  --config content_safety \
  --input "User request" \
  --output "Candidate agent response"
```

The control-plane API performs the same check and persists the result as tamper-evident PostgreSQL
evidence. A successful response includes an `evidence_id` and `created_at`; upstream transport or
protocol failures return HTTP 502 and do not create a partial artifact.

```bash
curl http://127.0.0.1:8000/api/v1/guardrails/configs
curl -X POST http://127.0.0.1:8000/api/v1/guardrails/check \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "meta/llama-3.1-8b-instruct",
    "config_id": "content_safety",
    "input_text": "User request",
    "output_text": "Candidate agent response"
  }'
curl http://127.0.0.1:8000/api/v1/guardrails/evidence
curl http://127.0.0.1:8000/api/v1/guardrails/evidence/EVIDENCE_ID
```

## Versioned Configuration Lifecycle

NeMo Guardrails discovers configuration IDs from folders containing `config.yml` or `config.yaml`.
The folder may also contain Colang flows, prompts, custom actions, initialization code, and knowledge
base documents. AgentEval schema v10 tracks that complete deployment unit as an immutable local
version plus a deterministic SHA-256 digest.

```bash
BUNDLE_SHA=$(uv run aecontrol guardrails digest configs/content_safety)
uv run aecontrol guardrails register \
  --config content_safety \
  --version 2026.07.1 \
  --bundle-sha256 "$BUNDLE_SHA" \
  --description "Expanded jailbreak and PII policy"

uv run aecontrol guardrails activate \
  --config content_safety \
  --version 2026.07.1

uv run aecontrol guardrails versions
uv run aecontrol guardrails activations --config content_safety
```

The digest covers every regular file's relative path, length, and content in stable path order.
Bundles must contain a root `config.yml` or `config.yaml`; symbolic links are rejected so content
outside the reviewed directory cannot enter the digest indirectly. A `(config_id, version)` pair can
be registered only once.

Activation first calls the upstream `/v1/rails/configs` endpoint and refuses a configuration ID that
is not currently discoverable. Every activation is appended with actor, time, and UUID. Activating a
previous version performs an auditable rollback without deleting or mutating history.

```bash
curl -X POST http://127.0.0.1:8000/api/v1/guardrails/config-versions \
  -H "Authorization: Bearer $AECONTROL_ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"config_id\":\"content_safety\",\"version\":\"2026.07.1\",\"bundle_sha256\":\"$BUNDLE_SHA\"}"

curl -X POST http://127.0.0.1:8000/api/v1/guardrails/config-activations \
  -H "Authorization: Bearer $AECONTROL_ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"config_id":"content_safety","version":"2026.07.1"}'
```

New checks automatically bind the active version, bundle digest, and activation ID into the signed
evidence envelope. Callers may also send `config_version`; a mismatch with the active version returns
HTTP 409 before inference. When no local version is active, the check remains backward compatible but
is explicitly marked unmanaged in typed evidence and browser views.

The trust boundary is precise: upstream discovery proves only that the server exposes the registered
configuration ID. NeMo's list API does not return bundle content or a digest, so the deployment
pipeline must independently ensure the running folder matches the registered SHA-256. The activation
record is an operator assertion tied to that verification, not remote attestation of server files.
See NVIDIA's [configuration structure](https://docs.nvidia.com/nemo/guardrails/configure-guardrails/overview)
and [configuration discovery API](https://docs.nvidia.com/nemo/guardrails/latest/run-rails/using-fastapi-server/list-guardrail-configs.html).

The browser dashboard includes total checks, intervention rate, and the ten most recent evidence
records. `/guardrails/evidence/EVIDENCE_ID` renders the submitted text, guardrailed response,
activated rails, and server statistics. Dynamic values are HTML-escaped, and the detail route uses the
same digest verification as the REST API before returning content.

When API authentication is enabled, configuration discovery and evidence retrieval require `read`;
executing and storing a check requires `write`, while registration and activation require `admin`.
The synchronous and asynchronous Python SDKs expose
`guardrail_configs`, `check_guardrails`, `list_guardrail_evidence`, and
`get_guardrail_evidence` with the same typed contracts.

The typed evidence contains the configuration and model, submitted and returned text, activated rails,
server statistics, and `passed_through`. Pass-through means the checked text was returned exactly; an
altered or refused response is an intervention. AgentEval does not infer safety from a hard-coded
refusal phrase or from a rail name.

Schema v5 introduced the complete typed envelope as JSONB alongside queryable configuration, model,
pass-through, and timestamp columns. Schema v10 adds the optional active version reference. The
canonical payload digest is included in the full
`/api/v1/integrity` audit. Detail reads return HTTP 409 without returning the untrusted payload when
the digest does not match.

`/metrics` exports `aecontrol_guardrail_evidence_total` and
`aecontrol_guardrail_interventions_total`. These gauges deliberately omit configuration, model,
prompt, and evidence labels to avoid sensitive or high-cardinality telemetry.

`NEMO_GUARDRAILS_API_KEY` adds an optional bearer credential. The key is transport-only and does not
appear in evidence. Protocol tests use an in-process server double, keeping CI deterministic and free
of model calls. Operators should treat activated-rail logs as potentially sensitive because custom
rails may include application-specific names or diagnostics.
