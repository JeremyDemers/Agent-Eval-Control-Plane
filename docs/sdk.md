# Python SDK

`aecontrol` exports synchronous and asynchronous clients that use the same Pydantic contracts as the
engine, database, and API.

```python
from aecontrol import AgentEvalClient

client = AgentEvalClient("http://127.0.0.1:8000")
job = client.enqueue_job(
    "examples/suites/coding_repair.yaml",
    "candidate_fixed",
    priority=10,
    labels={"runtime": "deterministic"},
)
completed = client.wait_for_job(job.job_id)
run = client.get_run(completed.run_id) if completed.run_id else None
```

`AsyncAgentEvalClient` provides matching coroutine methods and uses non-blocking polling for terminal
job state. Both clients support health and operational snapshots, direct evaluations, job listing and
cancellation, run retrieval, and comparison creation/retrieval.

The default HTTP transport accepts only absolute HTTP(S) URLs, supports caller-generated request IDs,
normalizes structured API and connection failures into `AgentEvalAPIError`, and rejects malformed JSON
or unexpected response shapes. Tests inject the transport protocol, allowing deterministic lifecycle
and timeout checks without a network server.

Run `make sdk-demo` to launch a temporary local service, execute the four-slice baseline through the
SDK, print the typed result summary, and shut the temporary service down.
