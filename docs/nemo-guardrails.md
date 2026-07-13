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

When API authentication is enabled, configuration discovery and evidence retrieval require `read`;
executing and storing a check requires `write`. The synchronous and asynchronous Python SDKs expose
`guardrail_configs`, `check_guardrails`, `list_guardrail_evidence`, and
`get_guardrail_evidence` with the same typed contracts.

The typed evidence contains the configuration and model, submitted and returned text, activated rails,
server statistics, and `passed_through`. Pass-through means the checked text was returned exactly; an
altered or refused response is an intervention. AgentEval does not infer safety from a hard-coded
refusal phrase or from a rail name.

Schema v5 stores the complete typed envelope as JSONB alongside queryable configuration, model,
pass-through, and timestamp columns. The canonical payload digest is included in the full
`/api/v1/integrity` audit. Detail reads return HTTP 409 without returning the untrusted payload when
the digest does not match.

`NEMO_GUARDRAILS_API_KEY` adds an optional bearer credential. The key is transport-only and does not
appear in evidence. Protocol tests use an in-process server double, keeping CI deterministic and free
of model calls. Operators should treat activated-rail logs as potentially sensitive because custom
rails may include application-specific names or diagnostics.
