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

The typed evidence contains the configuration and model, submitted and returned text, activated rails,
server statistics, and `passed_through`. Pass-through means the checked text was returned exactly; an
altered or refused response is an intervention. AgentEval does not infer safety from a hard-coded
refusal phrase or from a rail name.

`NEMO_GUARDRAILS_API_KEY` adds an optional bearer credential. The key is transport-only and does not
appear in evidence. Protocol tests use an in-process server double, keeping CI deterministic and free
of model calls. Operators should treat activated-rail logs as potentially sensitive because custom
rails may include application-specific names or diagnostics.
