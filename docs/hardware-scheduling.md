# Hardware-Aware Scheduling

Workers inspect their host at startup and refresh a normalized capability document in PostgreSQL on
every lease heartbeat.
Every worker advertises CPU support. When `nvidia-smi` is available and healthy, it also advertises
CUDA plus normalized GPU name, memory, and compute capability.

```json
{
  "accelerators": ["cpu", "cuda"],
  "gpus": [{
    "index": 0,
    "uuid": "GPU-34325e56-ec67-93e4-e415-bdf9a7e02850",
    "name": "NVIDIA RTX 5000 Ada Generation Laptop GPU",
    "memory_total_mb": 16376,
    "memory_used_mb": 30,
    "utilization_percent": 0,
    "temperature_celsius": 37,
    "power_draw_watts": 4.92,
    "compute_capability": "8.9"
  }],
  "labels": {"runtime": "deterministic"}
}
```

Jobs request one accelerator and optional exact-match labels. PostgreSQL evaluates compatibility
inside the atomic lease query: the requested accelerator must be in the worker's advertised list,
and worker labels must contain every requested label. An incompatible worker never owns or increments
the attempt count of a job it cannot execute.

CUDA jobs can also require static framebuffer capacity and compute capability, live free framebuffer
memory, and a maximum utilization percentage. Every requested constraint must be satisfied by the
same physical device; capacity and load signals from multiple GPUs are never combined. Admission
remains part of the locked claim query, so underqualified or saturated workers leave the job queued
without consuming an attempt. Schema v6 adds the load constraints through an in-place migration.

```bash
uv run aecontrol jobs enqueue \
  --suite examples/suites/coding_repair.yaml \
  --agent-version candidate_fixed \
  --accelerator cuda \
  --minimum-gpu-memory-mb 12000 \
  --minimum-cuda-compute-capability 8.9 \
  --minimum-gpu-memory-available-mb 10000 \
  --maximum-gpu-utilization-percent 30
```

`minimum_gpu_memory_mb` describes the device's static framebuffer capacity;
`minimum_gpu_memory_available_mb` describes live headroom calculated from total minus used memory.
When a job requests a live constraint, missing memory-use or utilization telemetry makes that device
ineligible rather than optimistically treating the sample as idle. Placement diagnostics distinguish
missing telemetry, insufficient free memory, excessive utilization, and requirements split across
different devices.

## GPU Queue Capacity Forecast

The read-only capacity forecast evaluates all queued CUDA jobs against the same placement function
used by per-job diagnostics. It sorts jobs by priority and creation time, then uses bipartite maximum
matching so flexible jobs can move to alternate workers instead of occupying the only worker capable
of running a constrained job.

```bash
uv run aecontrol jobs capacity
uv run aecontrol jobs capacity --json
curl http://127.0.0.1:8000/api/v1/capacity/gpu
```

Each job is classified as `first_wave`, `deferred`, or `blocked`. First-wave jobs have a dry-run worker
assignment. Deferred jobs match active workers but exceed the current one-job-per-worker scheduling
wave. Blocked jobs have no active eligible worker and retain the placement diagnostic's blocker.

`minimum_clearance_waves` is calculated by expanding each worker into successively larger wave slots
and finding the first complete matching for every compatible job. It is exact for the current static
eligibility graph; it does not predict execution duration, worker arrivals, telemetry changes, or GPU
load after process startup. Blocked jobs are excluded from the clearance count.

The forecast also summarizes active CUDA worker slots, visible devices, total and available
framebuffer memory, and average utilization. Prometheus exports low-cardinality queue-state,
clearance-wave, and active-worker gauges. The browser dashboard displays the same forecast and
first-wave worker assignments.

GPU discovery is optional and fail-safe. Missing binaries, timeouts, command failures, and malformed
device rows result in a CPU-only capability document. No synthetic GPU is reported. Operators can
inspect discovery with `aecontrol hardware --json`, and the browser dashboard shows registered worker
inventory and job requirements. `/metrics` exports per-device memory, utilization, temperature, and
power gauges using stable worker, GPU index, UUID, and model labels. Available framebuffer bytes are
exported directly using the same clamped calculation as admission. A sample timestamp accompanies each
device so alerting rules can reject stale worker telemetry.

Load-aware admission uses the worker's fresh pre-claim `nvidia-smi` sample. It reduces avoidable
contention but is not a reservation: GPU load can change between sampling and process startup.
Production GPU sharing should pair this signal with Kubernetes/NVIDIA device isolation or MIG and
runtime-level memory controls.
