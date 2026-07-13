# AgentEval Control Plane

[![CI](https://github.com/JeremyDemers/Agent-Eval-Control-Plane/actions/workflows/ci.yml/badge.svg)](https://github.com/JeremyDemers/Agent-Eval-Control-Plane/actions/workflows/ci.yml)
[![Security](https://github.com/JeremyDemers/Agent-Eval-Control-Plane/actions/workflows/security.yml/badge.svg)](https://github.com/JeremyDemers/Agent-Eval-Control-Plane/actions/workflows/security.yml)
[![Python 3.12](https://img.shields.io/badge/python-3.12-3776AB)](https://www.python.org/)
[![Typed](https://img.shields.io/badge/typing-py.typed-147A4B)](src/aecontrol/py.typed)
[![License: MIT](https://img.shields.io/badge/license-MIT-171A1F)](LICENSE)

`aecontrol` is a control plane for evaluating deterministic tool-using coding agents. It compares
agent versions, records normalized trajectories, detects aggregate and slice-level regressions,
enforces YAML release gates, and persists evaluation evidence in PostgreSQL behind a FastAPI service.

Aggregate scores are not enough for agents: a candidate can look mostly unchanged overall while
getting worse on a critical slice such as security validation. This project makes that failure mode
visible and blocks the release.

## Demo

```bash
uv sync --extra dev
make demo
```

The demo evaluates:

- `baseline`
- `candidate_regressed`
- `candidate_fixed`

It writes JSON and standalone HTML reports under `reports/`. The regressed candidate is blocked
because it drops hidden-test success on the `security_sensitive` slice. The fixed candidate passes.

![Regressed candidate report showing a blocked security-sensitive slice](docs/assets/regressed-report.png)

Expected demo summary:

```text
baseline: hidden pass rate 24/24
candidate_regressed: hidden pass rate 22/24
delta=-8.33% regressed=['SEC-01', 'SEC-04']
gate: BLOCK
candidate_fixed: hidden pass rate 24/24
delta=0.00% regressed=[]
gate: PASS
```

## Useful Commands

```bash
uv run aecontrol doctor
uv run aecontrol agents versions
uv run aecontrol datasets validate examples/datasets/coding_repair.jsonl
uv run aecontrol run --suite examples/suites/coding_repair.yaml --agent-version baseline --output reports/baseline.json
uv run aecontrol compare --baseline reports/baseline.json --candidate reports/regressed.json --output reports/regressed-comparison.json
uv run aecontrol gate --comparison reports/regressed-comparison.json --policy examples/policies/coding_repair_gate.yaml
uv run aecontrol report --comparison reports/regressed-comparison.json --policy examples/policies/coding_repair_gate.yaml --baseline-run reports/baseline.json --candidate-run reports/regressed.json --output reports/regressed.html
```

## Control Plane Service

For local development, the repository can create an unprivileged project PostgreSQL cluster on port
`55432`, so it does not require sudo or alter a system cluster. `PG_BIN` can override the server
binary directory when `pg_config` is not on `PATH`.

```bash
make service-demo
make serve
```

Open `http://127.0.0.1:8000` for the run and trace explorer or
`http://127.0.0.1:8000/docs` for the interactive OpenAPI contract. The service can execute and
persist evaluations, retrieve individual case trajectories, compare stored run IDs, apply release
policies, and inspect durable gate decisions. Its preferred execution path queues jobs for independent
workers using expiring PostgreSQL leases and bounded retries.

```bash
uv run aecontrol jobs enqueue --suite examples/suites/coding_repair.yaml --agent-version candidate_fixed --priority 10
uv run aecontrol worker --once
uv run aecontrol jobs list
uv run aecontrol hardware
```

The claim protocol uses `FOR UPDATE SKIP LOCKED`, supports crash recovery through lease expiration,
and prevents stale workers from acknowledging work they no longer own. See
[`docs/distributed-execution.md`](docs/distributed-execution.md) for the state machine and delivery
semantics.

API requests and durable jobs preserve W3C trace context across PostgreSQL queue boundaries. Local
runs emit structured JSON spans; setting `OTEL_EXPORTER_OTLP_ENDPOINT` enables batched OTLP/HTTP
protobuf export from APIs and workers without changing application code. See
[`docs/distributed-tracing.md`](docs/distributed-tracing.md) for collector configuration and the
telemetry privacy contract.

Workers refresh NVIDIA GPU telemetry on lease heartbeats. Local discovery uses `nvidia-smi`; setting
`AECONTROL_DCGM_EXPORTER_URL` promotes DCGM Exporter metrics to the live admission source, including
pod-mapped MIG telemetry. Jobs can request `cpu` or `cuda` and exact-match pool labels; Prometheus
exposes per-device memory, utilization, temperature, power, and telemetry provenance. Incompatible
workers skip jobs without consuming an attempt. See
[`docs/hardware-scheduling.md`](docs/hardware-scheduling.md) for the normalized capability contract.

CUDA jobs may require minimum framebuffer capacity, compute capability, live free memory, and a
maximum utilization level. PostgreSQL admits a lease only when one GPU satisfies the complete static
and load-aware request, preventing accidental cross-device aggregation and avoiding already saturated
devices. Missing load telemetry fails closed. Queued jobs expose placement diagnostics that identify
stale workers, accelerator and label mismatches, unavailable samples, and per-device GPU constraints
without consuming an execution attempt.

MIG-aware jobs can additionally require an exact NVIDIA partition profile. Workers advertise the
profile assigned by their orchestrator, and schema v8 applies it in the same atomic, single-device
lease predicate as memory and load. The Kubernetes mixed-strategy overlay includes `1g.10gb` and
`3g.40gb` worker pools for NVIDIA GPU Operator clusters.

```bash
uv run aecontrol jobs enqueue \
  --suite examples/suites/coding_repair.yaml \
  --agent-version nim/meta/llama-test \
  --accelerator cuda \
  --mig-profile 3g.40gb
kubectl apply -k deploy/overlays/mig
```

```bash
uv run aecontrol jobs explain JOB_ID
uv run aecontrol jobs capacity
uv run aecontrol jobs demand
curl http://127.0.0.1:8000/api/v1/capacity/gpu
curl http://127.0.0.1:8000/api/v1/capacity/gpu/demand
```

The GPU capacity forecast runs every queued CUDA job through the real accelerator, label, memory,
compute-capability, and live-load constraints. A priority-preserving maximum matching identifies the
next scheduling wave without wasting specialized workers, while worker-slot matching calculates the
minimum waves needed for all currently compatible jobs. The dashboard and Prometheus metrics separate
jobs blocked by missing capacity from compatible jobs deferred only by slot pressure.

Schema v9 records the start of each leased attempt and learns average and p90 execution duration from
the latest 500 completed CUDA jobs, including exact MIG request classes. When every compatible queued
job has matching history, the forecast combines p90 duration with the exact clearance-wave count to
publish a conservative queue ETA and an explicit sample-based confidence level. Missing history stays
`unavailable` rather than producing synthetic certainty.

The 24-hour GPU demand forecast groups up to eight weeks of durable CUDA arrivals by UTC
hour-of-week. Each future hour divides matching arrivals by the number of actually observed seasonal
slots, so zero-traffic hours remain part of the denominator. Predicted arrivals plus queued and
running work are converted to GPU seconds using completed-attempt average duration and compared with
active worker capacity. Confidence is high only after four weeks, 20 CUDA arrivals, and 10 duration samples;
otherwise the API reports `low` or `unavailable`. This is a capacity-planning signal, not a claim that
future workload behavior is deterministic.

Use `make serve PORT=8001` when port `8000` is already occupied.

![GPU capacity forecast matching NVIDIA A100 and L4 workers to queued NIM jobs](docs/assets/control-plane-dashboard.png)

Set `DATABASE_URL` to use an existing PostgreSQL deployment. The default is shown in `.env.example`.
API suite and policy files are restricted to `AECONTROL_INPUT_ROOT`, which defaults to `examples/`.
Long-lived APIs and workers can enable bounded Psycopg connection pools, while direct mode remains
available for PgBouncer and short-lived commands. Transaction-scoped advisory locks serialize schema
initialization across replicas. See [`docs/database.md`](docs/database.md) for TLS, sizing, migration,
and saturation-monitoring guidance.

API keys are permanently bound to tenant IDs. Schema v12 applies forced PostgreSQL row-level security
to evidence, jobs, policy history, and worker inventory while transaction-local context remains safe
across pooled connections. See [`docs/multi-tenancy.md`](docs/multi-tenancy.md) for worker topology,
KEDA, migration, and database-role boundaries.

Operational endpoints provide database health, queue-aware readiness, Prometheus-compatible metrics,
correlated request timing, and W3C Trace Context propagation. Queued jobs persist their originating
`traceparent` and request ID; workers continue the same trace after the PostgreSQL handoff.

```bash
curl http://127.0.0.1:8000/healthz
curl http://127.0.0.1:8000/readyz
curl http://127.0.0.1:8000/metrics
```

See [`docs/operations.md`](docs/operations.md) for metric semantics and request-ID behavior.
See [`docs/distributed-tracing.md`](docs/distributed-tracing.md) for durable trace propagation and
collector boundaries.

## Python SDK

The package exports typed synchronous and asynchronous clients for evaluations, durable jobs, runs,
comparisons, cancellation, waiting, health, and operations.

```python
from aecontrol import AgentEvalClient

client = AgentEvalClient("http://127.0.0.1:8000")
job = client.enqueue_job("examples/suites/coding_repair.yaml", "candidate_fixed")
completed = client.wait_for_job(job.job_id)
```

Run `make sdk-demo` for a self-contained live example. See [`docs/sdk.md`](docs/sdk.md) for sync and
async usage.

## Architecture

```mermaid
flowchart LR
  Clients[CLI / SDK / REST / Trace Explorer] --> API[FastAPI Control Plane]
  API --> Guardrails[NVIDIA NeMo Guardrails]
  Guardrails --> Evidence[Guardrail Evidence]
  Evidence --> PG
  API --> Queue[(PostgreSQL Job Queue)]
  Queue --> Workers[Leased Workers]
  Hardware[NVIDIA GPU / CPU Capabilities] --> Workers
  Workers --> Engine
  CLI[Typer CLI] --> Engine[Evaluation Engine]
  API --> Engine
  Engine --> Dataset[JSONL Dataset]
  Engine --> Runtime[Deterministic Coding Runtime]
  Runtime --> Sandbox[Temporary Workspace Tools]
  Engine --> Evaluators[Evaluator Plugins]
  Engine --> Run[EvaluationRun]
  Run --> PG[(PostgreSQL JSONB)]
  API --> PG
  Run --> Compare[RunComparison]
  Compare --> Gate[QualityGateDecision]
  Compare --> HTML[Reports / Trace Explorer]
```

## Docker

```bash
make docker-build
make docker-demo
```

The local Makefile uses native Podman by default because Snap-installed VS Code can break Docker
emulation through a revision-specific `XDG_DATA_HOME`. Set `CONTAINER_ENGINE=docker` if you want to
force Docker on a host with a healthy Docker daemon.

## Kubernetes

The Kustomize deployment separates the API, CPU workers, and NVIDIA GPU workers. GPU pods request the
standard `nvidia.com/gpu` extended resource while AgentEval performs its own memory and compute
capability admission after device discovery.

```bash
kubectl apply -f /tmp/aecontrol-secret.yaml
kubectl apply -k deploy/kubernetes
```

Tagged releases publish a GHCR image with an SBOM and build provenance. See
[`docs/kubernetes.md`](docs/kubernetes.md) for secret setup, rollout checks, and production boundaries.
The production CloudNativePG overlay provisions a three-instance PostgreSQL 17 cluster with
synchronous replication, quorum-guarded failover, topology spread, and an optional PodMonitor.
The Barman Cloud overlay adds continuous WAL archiving, encrypted daily base backups, a 30-day
recovery window, backup-health alerts, and an isolated point-in-time recovery template.
An optional KEDA overlay scales CPU and NVIDIA workers from durable PostgreSQL queue depth.
An independent MIG overlay consumes profile-specific resources exposed by NVIDIA GPU Operator's
mixed strategy and registers profile-aware worker pools.

## Release Artifacts

`make package` builds a wheel and source distribution, installs the wheel into a fresh Python 3.12
environment, verifies the typed public API, and runs the installed CLI. CI performs this smoke test
after the PostgreSQL suite.

Tags matching `v*` must match the package version. They create a GitHub Release containing both
distributions and GitHub artifact-provenance attestations.

```bash
make package
gh attestation verify dist/aecontrol-0.38.0-py3-none-any.whl \
  --repo JeremyDemers/Agent-Eval-Control-Plane
```

See [`docs/releases.md`](docs/releases.md) for the release contract and verification procedure.

## Execution Isolation

The default process sandbox enforces source-size, syntax, import/call, wall-clock, CPU, address-space,
file-size, descriptor, process-count, output, and environment limits. A rootless Podman backend adds a
read-only workspace, disabled networking, dropped Linux capabilities, `no-new-privileges`, an
unprivileged UID, container CPU/memory/PID limits, digest enforcement, and optional custom
seccomp/AppArmor policies.

```bash
make sandbox-demo
AECONTROL_SANDBOX_BACKEND=podman uv run aecontrol doctor
```

`make sandbox-demo` resolves the cached Python image to its immutable repository digest and runs all
four slices with `AECONTROL_SANDBOX_REQUIRE_DIGEST=true`. Every evaluation records `sandbox_backend`
provenance. See [`docs/security.md`](docs/security.md) for production configuration, kernel-policy
controls, and the remaining VM isolation boundary.

CodeQL, pull-request dependency review, and a weekly `uv.lock`-derived vulnerability audit run in
GitHub Actions. The local equivalent is:

```bash
uv export --frozen --no-dev --no-emit-project --format requirements-txt | \
  uvx pip-audit -r /dev/stdin
```

## Ollama Runtime

Ollama is an optional model-backed runtime; deterministic agents remain the required CI path. The
smoke suite evaluates one case from each slice with structured generation, fixed seed and temperature,
prompt hashing, full trajectory capture, and the same public/hidden tests used by deterministic runs.

```bash
uv run aecontrol ollama doctor
uv run aecontrol ollama models
make ollama-demo
```

Agent versions use `ollama/<model>`, such as `ollama/llama3.2:3b`. Queued Ollama jobs automatically
require the `runtime=ollama` worker label. Start a compatible worker with
`uv run aecontrol worker --label runtime=ollama`.

The checked local smoke run passed 1/4 hidden tests and was correctly blocked, revealing distinct
typing, async, and security failure modes. See
[`docs/ollama-evaluation.md`](docs/ollama-evaluation.md) for the evidence summary.

![Ollama smoke evaluation blocked after hidden-test regressions](docs/assets/ollama-report.png)

## OpenAI-Compatible Runtime

Agent versions such as `openai/llama3.2:3b` use a provider-neutral chat-completions adapter with
structured output, fixed generation settings, usage metadata, prompt hashing, and isolated failures.
The default endpoint is Ollama's local `/v1`; environment configuration can target compatible hosted
services or NVIDIA NIM deployments.

```bash
uv run aecontrol openai doctor
uv run aecontrol openai models
make openai-demo
```

See [`docs/openai-compatible.md`](docs/openai-compatible.md) for endpoint configuration and the limits
of the checked compatibility claim.

## NVIDIA NIM Runtime

The first-class `nim/` runtime supports hosted NVIDIA API Catalog and self-hosted NIM endpoints with
NVIDIA credential precedence, model discovery, management metadata, structured coding repairs, and
durable `runtime=nvidia-nim` worker placement.

```bash
NVIDIA_API_KEY=nvapi-... uv run aecontrol nim doctor
uv run aecontrol nim models
```

See [`docs/nvidia-nim.md`](docs/nvidia-nim.md) for hosted and self-hosted configuration, provenance,
and credential boundaries.

## LangGraph Runtime

The optional LangGraph adapter evaluates compiled state graphs through the same engine, deterministic
evaluators, release gates, and persisted trajectory contract as built-in runtimes. LangGraph v2 task,
state, message, custom, and subgraph events become bounded graph-node evidence; final root state maps
to a normal `AgentOutput`, including tool calls and sandbox test results.

```bash
uv sync --extra dev --extra langgraph
make langgraph-demo
```

The checked demo executes a two-node coding-repair graph against four slices and passes 4/4 hidden
tests without model credentials. State payload capture is disabled by default; opt-in payloads redact
configured secret keys, and graph failures, interrupts, oversized events, or runaway streams become
structured error evidence. See [`docs/langgraph.md`](docs/langgraph.md) for graph and output contracts.

## NeMo Guardrails Evidence

The typed NeMo Guardrails integration discovers server configurations and checks agent input/output
pairs with input and output rails only. Successful control-plane checks become indexed PostgreSQL
artifacts with stable IDs, timestamps, canonical SHA-256 digests, and fail-closed retrieval. Evidence
records exact pass-through versus intervention, activated rails, and server statistics without relying
on a provider-specific refusal phrase.

```bash
uv run aecontrol guardrails configs
uv run aecontrol guardrails check --model meta/llama-3.1-8b-instruct \
  --config content_safety --input "request" --output "agent response"

curl -X POST http://127.0.0.1:8000/api/v1/guardrails/check \
  -H 'Content-Type: application/json' \
  -d '{"model":"meta/llama-3.1-8b-instruct","config_id":"content_safety","input_text":"request","output_text":"agent response","expected_action":"intervention"}'
```

The browser explorer summarizes safety-check volume and intervention rate, links recent evidence to
escaped detail views, and refuses to render records that fail digest verification. Prometheus exports
low-cardinality check and intervention totals without model names, prompts, or evidence IDs.

Schema v10 adds an immutable configuration-version registry and append-only activation history.
Operators can deterministically hash a complete NeMo configuration directory, register the digest,
activate it only while the server advertises that configuration ID, roll back by reactivating an older
version, and bind active version, bundle SHA-256, and activation ID into signed check evidence.

```bash
BUNDLE_SHA=$(uv run aecontrol guardrails digest configs/content_safety)
uv run aecontrol guardrails register --config content_safety \
  --version 2026.07.1 --bundle-sha256 "$BUNDLE_SHA"
uv run aecontrol guardrails activate --config content_safety --version 2026.07.1
uv run aecontrol guardrails activations --config content_safety
uv run aecontrol guardrails efficacy --config content_safety --days 30
```

Schema v11 adds optional expected-action labels to signed evidence and compares policy versions with
label coverage, intervention rate, confusion matrices, accuracy, precision, recall, and false-positive
rate. `GET /api/v1/guardrails/efficacy` supports configuration and timezone-aware date-window filters;
the dashboard presents a 30-day version comparison without treating unlabeled historical checks as
correct outcomes.

![NeMo Guardrails intervention evidence with activated rails and server statistics](docs/assets/guardrail-evidence.png)

See [`docs/nemo-guardrails.md`](docs/nemo-guardrails.md) for evidence semantics and log sensitivity.

## Scoped API Authentication

Production-style bearer authentication can be enabled without changing the zero-configuration local
demo. API keys are stored as SHA-256 digests, compared in constant time, assigned `read`, `write`, or
`admin` scopes, represented in OpenAPI, and attributed by key ID in structured request logs.

```bash
uv run aecontrol auth hash-key
uv run aecontrol auth validate auth.yaml
AECONTROL_AUTH_CONFIG=auth.yaml make serve
```

See [`docs/authentication.md`](docs/authentication.md) for configuration and rotation guidance.

## Signed Artifact Authenticity

Persisted runs, comparisons, and NeMo Guardrails checks carry canonical SHA-256 digests and can be
authenticated with an HMAC keyring held outside PostgreSQL. Reads fail closed on digest mismatch,
invalid signature, or an unavailable historical key; audits separately report signed and legacy
unsigned evidence without returning artifact payloads.

```bash
uv run aecontrol store generate-signing-key
uv run aecontrol store verify
curl http://127.0.0.1:8000/api/v1/integrity
```

Schema v7 adds optional HMAC-SHA256 signatures and rotation-friendly key IDs while preserving
in-place upgrades and readable unsigned legacy evidence. See
[`docs/artifact-integrity.md`](docs/artifact-integrity.md) for configuration, rotation, and threat
model limits.

## Current Limitations

The browser explorer is intentionally local-trust for this portfolio phase. The default process
backend is not hardened isolation for untrusted code, while the stronger Podman backend still shares
the host kernel. The project consumes but does not install or reconfigure NVIDIA GPU Operator,
DCGM Exporter, CloudNativePG, Barman Cloud Plugin, cert-manager, or Prometheus Operator. Automated
restore drills, cross-region promotion, additional hosted providers, immutable evidence storage,
self-service tenant administration, and cross-tenant fleet analytics remain in `docs/roadmap.md`.

## Project Governance

Contributions are welcome through focused issues and pull requests. See
[`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md), and
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) for validation, disclosure, and participation guidance.
