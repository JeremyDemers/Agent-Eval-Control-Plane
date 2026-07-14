# Python SDK

`aecontrol` exports synchronous and asynchronous clients that use the same Pydantic contracts as the
engine, database, and API.

```python
from aecontrol import AgentEvalClient, ExpectedGuardrailAction
from aecontrol.models import Accelerator

client = AgentEvalClient("http://127.0.0.1:8000", api_key="your-high-entropy-key")
job = client.enqueue_job(
    "examples/suites/coding_repair.yaml",
    "candidate_fixed",
    priority=10,
    labels={"runtime": "deterministic"},
    accelerator=Accelerator.CUDA,
    minimum_gpu_memory_available_mb=10000,
    maximum_gpu_utilization_percent=30,
)
placement = client.explain_job(job.job_id)
capacity = client.gpu_capacity()
demand = client.gpu_demand()
integrity = client.verify_artifacts()
completed = client.wait_for_job(job.job_id)
run = client.get_run(completed.run_id) if completed.run_id else None
guardrail = client.check_guardrails(
    "meta/llama-3.1-8b-instruct",
    "content_safety",
    "User request",
    "Candidate agent response",
    expected_action=ExpectedGuardrailAction.INTERVENTION,
)
efficacy = client.guardrail_efficacy(config_id="content_safety")
```

`AsyncAgentEvalClient` provides matching coroutine methods and uses non-blocking polling for terminal
job state. Both clients support health and operational snapshots, direct evaluations, job listing,
placement diagnostics, sample-qualified GPU queue capacity and seasonal demand forecasts,
artifact-integrity audits and cancellation, run retrieval, comparison creation/retrieval, and durable
NeMo Guardrails evidence workflows.

Guardrails lifecycle methods include `guardrail_config_versions`,
`register_guardrail_config_version`, `guardrail_config_activations`, and
`activate_guardrail_config`. `check_guardrails(..., config_version="2026.07.1")` fails with a conflict
if that version is no longer active, allowing deployment automation to detect policy drift.
`check_guardrails(..., expected_action=ExpectedGuardrailAction.INTERVENTION)` stores a supervised
label in signed evidence. `guardrail_efficacy` then returns typed, per-version confusion matrices and
derived metrics; the asynchronous client exposes the same method.

Platform automation can use `tenants`, `create_tenant`, and `set_tenant_status` with an `operator`
credential. Tenant admins use `tenant`, `tenant_api_keys`, `issue_tenant_api_key`, and
`revoke_tenant_api_key`; issued secrets appear only in the returned `IssuedTenantAPIKey`. The
asynchronous client has matching coroutine methods. See
[`tenant-lifecycle.md`](tenant-lifecycle.md) for scope separation and rotation invariants.

The default HTTP transport accepts only absolute HTTP(S) URLs, supports caller-generated request IDs,
normalizes structured API and connection failures into `AgentEvalAPIError`, and rejects malformed JSON
or unexpected response shapes. Tests inject the transport protocol, allowing deterministic lifecycle
and timeout checks without a network server.

Run `make sdk-demo` to launch a temporary local service, execute the four-slice baseline through the
SDK, print the typed result summary, and shut the temporary service down.
