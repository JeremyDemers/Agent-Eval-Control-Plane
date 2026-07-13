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

The default image is `ghcr.io/jeremydemers/agent-eval-control-plane:0.24.0`. Tagged releases publish
multi-layer OCI images with an SBOM and build provenance. Override the image in an environment overlay
when promoting by digest.

The included PostgreSQL instance is for portfolio and development clusters. Production deployments
should use a managed PostgreSQL service, external secret management, network policies, TLS ingress,
autoscaling, and a dedicated storage class. GPU nodes must have NVIDIA drivers and the NVIDIA device
plugin installed; the manifests do not install cluster-level GPU operators.

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
