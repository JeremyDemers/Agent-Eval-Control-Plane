# Roadmap

Implemented ahead of the original four-day scope:

- FastAPI service with OpenAPI documentation
- PostgreSQL JSONB persistence and schema versioning
- Browser run, comparison, and trace explorer
- Async evaluation jobs with priorities, retries, cancellation, and resumable worker leases
- Capability-aware CPU/CUDA placement and registered worker inventory
- Optional Ollama coding runtime with structured output and provenance
- Resource-limited process sandbox and rootless networkless Podman execution backend
- Typed synchronous and asynchronous Python SDK
- OpenAI-compatible model runtime with local compatibility verification
- Scoped API-key authentication with constant-time digest verification
- Heartbeat-refreshed NVIDIA GPU telemetry and Prometheus device gauges
- Atomic CUDA admission by per-device memory and compute capability
- Explainable queue placement diagnostics across API, CLI, dashboard, and SDK
- Canonical SHA-256 integrity verification for persisted evaluation evidence
- Reproducible Python distributions with clean-install CI and release attestations
- CodeQL, dependency review, and frozen-lock vulnerability auditing
- W3C trace-context propagation through durable PostgreSQL jobs
- Kubernetes API and CPU/NVIDIA worker deployment with GHCR release images
- Queue-aware KEDA scaling for CPU and NVIDIA workers
- First-class NVIDIA NIM runtime for hosted and self-hosted endpoints
- Typed NeMo Guardrails input/output evidence and activated-rail diagnostics

Next stages:

- Pinned sandbox images with seccomp/AppArmor and microVM isolation
- Production database/operator integration and predictive GPU capacity planning
- Additional hosted provider authentication and endpoint-specific adapters
- Deeper NeMo configuration lifecycle and LangGraph interoperability packages
- Multi-tenancy, signed immutable object storage, and external trace/metrics backends
