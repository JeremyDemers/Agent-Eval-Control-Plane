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
- Load-aware CUDA admission by live free memory and utilization
- Explainable queue placement diagnostics across API, CLI, dashboard, and SDK
- Canonical SHA-256 integrity verification for persisted evaluation evidence
- Reproducible Python distributions with clean-install CI and release attestations
- CodeQL, dependency review, and frozen-lock vulnerability auditing
- W3C trace-context propagation through durable PostgreSQL jobs
- Kubernetes API and CPU/NVIDIA worker deployment with GHCR release images
- Queue-aware KEDA scaling for CPU and NVIDIA workers
- First-class NVIDIA NIM runtime for hosted and self-hosted endpoints
- Durable, tamper-evident NeMo Guardrails checks across REST and sync/async SDKs
- Browser Guardrails evidence explorer and low-cardinality safety metrics
- Rotation-aware HMAC-SHA256 authenticity for persisted evaluation evidence
- Priority-preserving GPU queue forecasts with exact static clearance-wave matching
- Exact NVIDIA MIG profile admission and a GPU Operator mixed-strategy deployment overlay
- Historical CUDA/MIG duration evidence and sample-qualified GPU queue clearance ETA
- Immutable NeMo Guardrails bundle versions, append-only activation history, and evidence provenance
- Supervised NeMo Guardrails policy efficacy with per-version confusion matrices and bounded trends
- LangGraph v2 runtime interoperability with graph-node, subgraph, tool, and failure evidence
- Batched OpenTelemetry OTLP/HTTP trace export across API and durable worker boundaries
- Digest-enforced Podman sandboxes with configurable seccomp/AppArmor policy and hardened GPU pods
- Bounded PostgreSQL connection pools, saturation metrics, and advisory-locked schema initialization
- DCGM Exporter-backed full-GPU and pod-mapped MIG admission telemetry
- Evidence-qualified UTC hour-of-week GPU demand and saturation forecasting
- Three-instance CloudNativePG provisioning with synchronous quorum failover and opt-in monitoring
- Barman Cloud WAL archiving, daily base backups, 30-day retention, PITR template, and backup alerts
- API-key-bound tenants with forced PostgreSQL RLS across evidence, queues, policies, and workers
- Ed25519 evidence attestations with public-key-only verification and legacy HMAC migration
- Tenant-scoped append-only evidence ledger with hash-chain and source-deletion verification
- Self-service tenant lifecycle with isolated operator scope, key rotation, and suspension
- Ed25519 ledger checkpoints with S3 Object Lock compliance retention and rollback detection
- Atomic per-tenant queue, submission-rate, execution, and CUDA concurrency quotas
- OIDC JWT federation with bounded JWKS rotation and tenant/scope claim enforcement
- Privacy-bounded cross-tenant CPU/CUDA fleet analytics with transactional PostgreSQL rollups
- Version-pinned Vault Transit Ed25519 signing with offline public-key verification
- Scheduled CloudNativePG restore drills with immutable report archival and bounded cleanup

Next stages:

- VM or microVM isolation for actively hostile candidate code
- Cross-region PostgreSQL replica promotion and recovery-object replication
- Additional hosted provider authentication and endpoint-specific adapters
- Cross-region evidence replication and direct cloud KMS/HSM signing adapters
