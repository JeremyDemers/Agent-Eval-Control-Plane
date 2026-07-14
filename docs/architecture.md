# Architecture

AgentEval Control Plane is local-first but now has two entry points over one domain layer. The Typer
CLI supports CI and offline artifact workflows. The FastAPI service exposes evaluations, stored runs,
case trajectories, comparisons, and release decisions to API clients and the browser trace explorer.

The evaluation engine loads a versioned JSONL dataset, invokes a runtime adapter for each case, runs
deterministic evaluators, then emits immutable run artifacts. PostgreSQL stores the complete Pydantic
contracts as JSONB while indexing identity, version, timestamps, pass rate, gate outcome, and aggregate
delta for control-plane queries. A schema metadata table rejects unsupported storage versions.
NeMo Guardrails checks use the same tamper-evident artifact path and have browser/API detail views that
verify canonical payload digests before rendering evidence.

Runtime adapters and evaluators use typed protocols so future integrations can be added without
rewriting the core engine.

`EvaluationEngine` accepts an injected runtime protocol. The optional LangGraph adapter consumes
compiled graph v2 streams, records bounded node/subgraph activity, and maps final root state into the
same `AgentOutput` contract as built-in runtimes. LangGraph remains an optional dependency, and graph
construction stays in trusted application code rather than accepting arbitrary imports over HTTP.

The coding-repair demo models each agent version as a strategy class. The runtime resolves
`baseline`, `candidate_regressed`, or `candidate_fixed`, then executes the same dataset and evaluator
suite for each version. This keeps agent behavior separate from comparison and quality-gate logic.

Short-lived commands open direct PostgreSQL connections, while long-lived API and worker processes
can use explicitly bounded, health-checked Psycopg pools. Every operation commits one artifact
transaction at a time. Transaction-scoped advisory locks serialize schema initialization across
replicas without leaving session locks behind after failures. Integration tests allocate a unique
schema, exercise the full HTTP workflow, and drop that schema on completion. GitHub Actions runs the
same tests against a PostgreSQL service container.

Evaluation admission is decoupled from execution through durable jobs. Workers claim priority-ordered
rows with `FOR UPDATE SKIP LOCKED`, heartbeat expiring leases, and retry failures up to a per-job
budget. This design supports horizontal worker scaling without introducing a separate queue service.
Schema v17 wraps tenant quota checks and state transitions in a tenant-local transaction advisory
lock, preserving queue, total execution, and CUDA concurrency limits across replicas.

Workers register normalized CPU, NVIDIA GPU, and operator-label capabilities. Accelerator and label
requirements are evaluated inside the atomic claim query, keeping incompatible jobs out of a worker's
lease and retry history.

Operational health, readiness, and Prometheus metrics are derived from the same transactional tables
as scheduling decisions. Request IDs and server timing connect API calls to structured logs without
placing model prompts, patches, or high-cardinality artifact identifiers in metric labels.
W3C trace context is persisted with queued work, allowing the API server span and asynchronous worker
consumer span to remain in one trace. A process-local backend keeps JSON logging as the default and
can activate a batched OpenTelemetry OTLP/HTTP exporter entirely through standard environment
configuration.

Authentication accepts opaque AgentEval keys or issuer-signed JWTs through one authorization path.
Federation verifies keys and claims before constructing the same tenant-bound `Principal` used by
API keys, so endpoint scope dependencies and PostgreSQL context are shared rather than duplicated.
