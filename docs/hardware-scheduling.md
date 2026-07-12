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

CUDA jobs can also require framebuffer capacity and compute capability. Both constraints must be
satisfied by the same physical device; capacities from multiple GPUs are never combined. Admission
remains part of the locked claim query, so underqualified workers leave the job queued without
consuming an attempt.
Existing schema-v1 databases are migrated in place to schema v2 when the service initializes.

```bash
uv run aecontrol jobs enqueue \
  --suite examples/suites/coding_repair.yaml \
  --agent-version candidate_fixed \
  --accelerator cuda \
  --minimum-gpu-memory-mb 12000 \
  --minimum-cuda-compute-capability 8.9
```

GPU discovery is optional and fail-safe. Missing binaries, timeouts, command failures, and malformed
device rows result in a CPU-only capability document. No synthetic GPU is reported. Operators can
inspect discovery with `aecontrol hardware --json`, and the browser dashboard shows registered worker
inventory and job requirements. `/metrics` exports per-device memory, utilization, temperature, and
power gauges using stable worker, GPU index, UUID, and model labels. A sample timestamp accompanies
each device so alerting rules can reject stale worker telemetry.
