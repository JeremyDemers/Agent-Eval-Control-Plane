# Hardware-Aware Scheduling

Workers inspect their host at startup and register a normalized capability document in PostgreSQL.
Every worker advertises CPU support. When `nvidia-smi` is available and healthy, it also advertises
CUDA plus normalized GPU name, memory, and compute capability.

```json
{
  "accelerators": ["cpu", "cuda"],
  "gpus": [{
    "name": "NVIDIA RTX 5000 Ada Generation Laptop GPU",
    "memory_total_mb": 16376,
    "compute_capability": "8.9"
  }],
  "labels": {"runtime": "deterministic"}
}
```

Jobs request one accelerator and optional exact-match labels. PostgreSQL evaluates compatibility
inside the atomic lease query: the requested accelerator must be in the worker's advertised list,
and worker labels must contain every requested label. An incompatible worker never owns or increments
the attempt count of a job it cannot execute.

GPU discovery is optional and fail-safe. Missing binaries, timeouts, command failures, and malformed
device rows result in a CPU-only capability document. No synthetic GPU is reported. Operators can
inspect discovery with `aecontrol hardware --json`, and the browser dashboard shows registered worker
inventory and job requirements.
