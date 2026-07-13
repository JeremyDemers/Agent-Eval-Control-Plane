# Kubernetes Deployment

The Kustomize base deploys two API replicas, two CPU workers, one NVIDIA GPU worker, and a development
PostgreSQL StatefulSet. The GPU worker requests one extended `nvidia.com/gpu` resource and relies on
the NVIDIA device plugin to inject a healthy device and `nvidia-smi` support. AgentEval then advertises
the discovered device inventory and applies its own per-device memory and compute-capability admission.

Create the database secret before applying the base:

```bash
cp deploy/kubernetes/secret.example.yaml /tmp/aecontrol-secret.yaml
# Replace every placeholder, including the generated artifact signing key, then:
kubectl apply -f /tmp/aecontrol-secret.yaml
kubectl apply -k deploy/kubernetes
kubectl -n aecontrol rollout status deployment/api
kubectl -n aecontrol port-forward service/api 8000:8000
```

The API and both worker pools receive the same external artifact-signing keyring from the Secret.
During rotation, retain old keys in `artifact-signing-keys`, change `artifact-signing-key-id`, and
restart every workload before verifying the store. A production cluster should source these values
from an external secret manager rather than committing key material.

API, CPU worker, full-GPU worker, and MIG worker pods run as non-root with Kubernetes
`RuntimeDefault` seccomp confinement. Every application container disables privilege escalation and
drops all Linux capabilities. Cluster policy should enforce these fields at admission and apply a
tested `Localhost` seccomp or AppArmor profile where the workload threat model requires tighter
syscall controls.

The default image is `ghcr.io/jeremydemers/agent-eval-control-plane:0.35.0`. Tagged releases publish
multi-layer OCI images with an SBOM and build provenance. Override the image in an environment overlay
when promoting by digest.

To export distributed traces, inject the same collector configuration into the API and every worker
deployment. The repository does not bundle or operate a collector:

```bash
kubectl -n aecontrol set env deployment/api deployment/worker-cpu deployment/worker-gpu \
  OTEL_SERVICE_NAME=aecontrol \
  OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector.observability:4318 \
  OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
kubectl -n aecontrol rollout status deployment/api
```

Place authenticated exporter headers in a Secret-backed environment variable, not directly in a
Kustomization or shell history. See [`distributed-tracing.md`](distributed-tracing.md) for supported
variables and attribute limits.

The included PostgreSQL instance is for portfolio and development clusters. Production deployments
should use a managed PostgreSQL service, external secret management, network policies, TLS ingress,
autoscaling, and a dedicated storage class. GPU nodes must have NVIDIA drivers and the NVIDIA device
plugin installed; the manifests do not install cluster-level GPU operators.

The GPU and MIG workers consume the GPU Operator's DCGM Exporter service at
`nvidia-dcgm-exporter.gpu-operator.svc.cluster.local:9400`. Change
`AECONTROL_DCGM_EXPORTER_URL` when the operator uses another namespace or service name. Enable the
exporter's Kubernetes mapping so samples contain workload `pod` labels; the worker uses its hostname
as the default selector and fails live placement constraints closed when the endpoint or mapping is
unavailable. NetworkPolicy must permit worker egress to TCP 9400. `aecontrol doctor` prints the
sanitized destination and timeout for rollout checks.

For a managed database, place the provider URL and TLS parameters in the existing database Secret.
Pool limits apply per process, so budget the sum across API, CPU, GPU, and MIG replicas. Pooling is
opt-in; this keeps the base compatible with PgBouncer and low-connection development clusters. See
[`database.md`](database.md) for configuration and saturation metrics.

## NVIDIA MIG Workers

The MIG overlay adds `1g.10gb` and `3g.40gb` worker deployments while retaining the base workloads.
It expects NVIDIA GPU Operator to be installed with `mig.strategy=mixed` and the target node geometry
to expose both profile resources. The overlay does not enable MIG mode or change node geometry.

```bash
kubectl apply -f /tmp/aecontrol-secret.yaml
kubectl apply -k deploy/overlays/mig
kubectl -n aecontrol get pods -l app.kubernetes.io/part-of=aecontrol
kubectl describe node | grep 'nvidia.com/mig-'
```

Each worker requests exactly one profile-specific resource, selects nodes labeled
`nvidia.com/mig.strategy=mixed`, and sets `AECONTROL_MIG_PROFILE` to the matching normalized profile.
This joins Kubernetes isolation to AgentEval's PostgreSQL admission: a job requesting `3g.40gb`
cannot be claimed by the full-GPU worker or the `1g.10gb` pool. Adjust `workers.yaml` when the cluster's
MIG geometry differs.

See NVIDIA's [GPU Operator MIG documentation](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/gpu-operator-mig.html)
for operator installation, mixed-strategy resources, node labels, and geometry management. The
overlay configures
[DCGM Exporter](https://docs.nvidia.com/datacenter/dcgm/latest/gpu-telemetry/dcgm-exporter.html) as
the per-instance admission telemetry source. The exporter remains owned by NVIDIA GPU Operator.

## Queue-Aware Autoscaling

The optional KEDA overlay scales workers from PostgreSQL queue depth. CPU workers target four
claimable jobs per replica and retain one warm replica. GPU workers target one CUDA job per replica
and scale from zero to four, allowing expensive GPU nodes to remain unused when no CUDA evaluation is
queued. Expired leases are included so replacement capacity appears after worker loss.

Install KEDA and Metrics Server before applying this overlay:

```bash
kubectl apply -f /tmp/aecontrol-secret.yaml
kubectl apply -k deploy/overlays/keda
kubectl -n aecontrol get hpa,scaledobjects
```

The API HPA scales from two to eight replicas at 70% average CPU. KEDA scaler failures retain two CPU
workers and one GPU worker. Production operators should tune targets, maxima, and stabilization windows
against evaluation duration, GPU quota, startup latency, and database connection limits.
