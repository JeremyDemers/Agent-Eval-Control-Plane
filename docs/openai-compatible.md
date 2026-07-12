# OpenAI-Compatible Runtime

Agent versions prefixed with `openai/` use a provider-neutral chat-completions adapter. The adapter
supports model discovery, JSON-schema structured output, fixed temperature and seed, token usage,
finish reason, prompt hashing, endpoint provenance, and per-case error isolation.

The default endpoint is local Ollama at `http://127.0.0.1:11434/v1`. Configure another compatible
service with environment variables:

```bash
export OPENAI_COMPAT_BASE_URL="https://your-endpoint.example/v1"
export OPENAI_COMPAT_API_KEY="..."
export OPENAI_COMPAT_MODEL="your-model"
make openai-demo
```

Queued jobs automatically require `runtime=openai-compatible`. A compatible worker can advertise that
capability with `aecontrol worker --label runtime=openai-compatible`.

NVIDIA NIM deployments that expose the OpenAI chat-completions contract are an intended target for
this adapter. The included verification uses local Ollama rather than an NVIDIA-hosted endpoint, so
the repository does not claim NIM-specific performance or compatibility beyond the shared protocol.

The checked local run of `openai/llama3.2:3b` reproduced the native Ollama result: arithmetic passed;
typing, async, and security hidden tests failed; and the release gate returned `BLOCK`. All four cases
captured provider provenance and token usage.
