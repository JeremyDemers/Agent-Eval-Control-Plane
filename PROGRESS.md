# Progress

## Four-Day Scope

- Build a polished offline vertical slice around deterministic coding-agent evaluation.
- Build database/API depth after the original deterministic demo is stable.

## Milestones

- Day 1: repository/tooling, contracts, dataset ingestion, plugin protocols.
- Day 2: deterministic coding runtime, temporary workspace tools, evaluators.
- Day 3: comparison, quality gate, HTML reports, CLI, tests.
- Day 4: Docker, CI, documentation polish, screenshots/report artifacts.

## Current Status

- Rebuilt from the revised project brief.
- Required four-day vertical slice is implemented locally.
- `make demo` evaluates baseline, regressed, and fixed candidates.
- Regressed candidate is blocked on `security_sensitive` hidden-test success.
- Fixed candidate passes the same quality gate.
- JSON and standalone HTML reports are generated under `reports/`.
- README includes a generated screenshot of the blocked HTML report.
- Agent versions are explicit strategy classes with example metadata.
- PostgreSQL-backed API and browser trace explorer are implemented.

## Implemented

- Python 3.12 `uv` package and Typer CLI named `aecontrol`.
- Pydantic v2 contracts for datasets, runs, trajectories, comparisons, and quality gates.
- Typed runtime/evaluator plugin protocols and local registry.
- Deterministic coding runtime with temporary workspace execution.
- Tool-style trajectory capture for file reads, code search, patch application, and tests.
- 24 JSONL coding-repair cases across `general_python`, `typing_required`, `async_python`, and `security_sensitive`.
- Baseline, regressed, and corrected deterministic agent behavior.
- Deterministic evaluators, paired comparison, per-metric deltas, bootstrap CI, YAML quality policy, and HTML reporting.
- Unit, property, contract, and E2E tests.
- Dockerfile, Podman-compatible container commands, and GitHub Actions workflow.
- PostgreSQL JSONB artifact store with schema versioning and indexed run/comparison summaries.
- FastAPI endpoints for health, evaluation execution, runs, case traces, comparisons, and gates.
- Operational browser views for persisted runs, trajectories, and release decisions.
- Project-owned PostgreSQL lifecycle scripts and database-backed service demo.
- Durable evaluation queue with priority ordering, bounded retries, cancellation, heartbeats, and lease recovery.
- Horizontally scalable workers using PostgreSQL `FOR UPDATE SKIP LOCKED` claims.
- Capability-aware placement with fail-safe NVIDIA GPU discovery and worker inventory.
- Optional Ollama coding runtime with structured output, deterministic settings, and error isolation.
- Prometheus metrics, queue-aware readiness, request correlation, and server timing.
- Policy-driven process isolation and a rootless, networkless Podman sandbox backend.
- Typed synchronous/asynchronous SDK with transport injection and terminal job waiting.
- OpenAI-compatible runtime with structured chat completions and local protocol verification.
- Optional scoped API-key authentication with OpenAPI integration and principal audit logging.
- Heartbeat-refreshed NVIDIA GPU utilization, memory, temperature, and power telemetry.
- Atomic per-device CUDA admission using memory and compute-capability requirements.
- Explainable queue placement diagnostics with per-worker blocker analysis.
- Tamper-evident run and comparison payloads with full-store integrity audits.
- Reproducible wheel/sdist packaging with clean-install and provenance-attested releases.
- CodeQL, dependency review, and weekly frozen-lock vulnerability scanning.
- Public contribution, disclosure, ownership, issue, and pull-request governance.
- W3C trace-context propagation across HTTP requests, PostgreSQL jobs, and workers.
- Kustomize deployment for replicated APIs, CPU workers, and NVIDIA GPU workers.
- Tagged GHCR image publication with OCI provenance and SBOM attestations.
- Queue-aware KEDA autoscaling for CPU and NVIDIA workers with failure fallbacks.
- NVIDIA NIM runtime with secure hosted credentials, self-hosted management APIs, and worker placement.
- NeMo Guardrails validation evidence with exact intervention detection and activated-rail diagnostics.

## Verification

- `uv sync --extra dev`: passed.
- `uv run ruff format . && uv run ruff check .`: passed.
- `uv run mypy`: passed with strict settings.
- `uv run pytest`: full suite passes with an enforced 85% coverage floor, including PostgreSQL/API, schema migration, tracing, artifact integrity, authentication, GPU telemetry, admission and diagnostics, worker, Ollama, OpenAI-compatible runtime, sandbox, observability, and SDK tests.
- `make demo`: passed; regressed candidate produced BLOCK, fixed candidate produced PASS.
- `make docker-build && make docker-demo`: passed with native Podman.
- `make package && uvx twine check dist/*`: wheel/sdist build, clean installation, typed API, CLI, and metadata checks passed.
- `uvx pip-audit` against exported locked runtime dependencies: no known vulnerabilities found.
- `make sandbox-demo`: 4/4 cases passed through networkless, read-only rootless Podman containers.
- `make sdk-demo`: live typed SDK evaluation passed 4/4 hidden tests against a temporary service.
- `make ollama-demo`: completed against local `llama3.2:3b`; 1/4 hidden tests passed and the release gate correctly returned BLOCK.
- `make openai-demo`: completed through Ollama's OpenAI-compatible `/v1` API; 1/4 hidden tests passed and the release gate correctly returned BLOCK.
- `docs/assets/regressed-report.png`: regenerated from `reports/regressed.html` with headless Chrome.

## Known Limitations

- Local temporary workspaces are not a hardened sandbox for untrusted code.
- Docker-compatible Makefile targets default to `podman` locally. Set `CONTAINER_ENGINE=docker` on hosts with a healthy Docker daemon.
- The browser explorer remains local-trust; durable workers are implemented, but production process supervision is deferred.
- Kubernetes database/operator integration, hardened worker isolation, additional hosted providers, multi-tenancy, LangGraph, and deeper NeMo configuration lifecycle support remain on the roadmap.
