# NVIDIA NIM Runtime

Agent versions prefixed with `nim/` use NVIDIA NIM's OpenAI-compatible chat-completions contract while
recording `nvidia-nim` provider provenance. The adapter supports model discovery, structured repair,
token usage, prompt hashing, deterministic generation settings, and NIM deployment metadata.

Hosted NVIDIA API Catalog:

```bash
export NVIDIA_API_KEY=nvapi-...
export NIM_BASE_URL=https://integrate.api.nvidia.com/v1
uv run aecontrol nim doctor
uv run aecontrol nim models
uv run aecontrol run --suite examples/suites/ollama_smoke.yaml \
  --agent-version nim/meta/llama-3.1-8b-instruct --output reports/nim.json
```

Self-hosted NIM does not require an AgentEval-side API key when its endpoint is trusted locally:

```bash
export NIM_BASE_URL=http://nim-service:8000/v1
uv run aecontrol nim metadata
```

Queued `nim/` jobs require workers advertising `runtime=nvidia-nim`. Kubernetes CPU workers expose
that capability because they orchestrate calls to a separately deployed NIM endpoint; the NIM service,
not the AgentEval worker, owns GPU inference. Secrets are read from `NVIDIA_API_KEY` or the legacy
`NIM_API_KEY` fallback and are never copied into run metadata, trajectories, logs, or job rows.

NIM management endpoints vary by deployment. `nim metadata` targets self-hosted `/v1/metadata` and
`/v1/version`; API Catalog users should rely on `nim doctor` and `nim models`. Protocol tests use an
in-process transport double, so CI validates handling without external inference cost or credentials.
