# Roadmap

Implemented ahead of the original four-day scope:

- FastAPI service with OpenAPI documentation
- PostgreSQL JSONB persistence and schema versioning
- Browser run, comparison, and trace explorer
- Async evaluation jobs with priorities, retries, cancellation, and resumable worker leases
- Capability-aware CPU/CUDA placement and registered worker inventory
- Optional Ollama coding runtime with structured output and provenance
- Resource-limited process sandbox and rootless networkless Podman execution backend

Next stages:

- Python SDK client
- Pinned sandbox images with seccomp/AppArmor and microVM isolation
- Kubernetes sharded jobs
- OpenAI-compatible and hosted LLM runtime adapters
- NeMo and LangGraph interoperability packages
- Authentication, multi-tenancy, object storage, metrics, and observability
