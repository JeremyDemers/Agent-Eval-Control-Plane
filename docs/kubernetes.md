# Kubernetes Deployment

The Kustomize base deploys two API replicas, two CPU workers, one NVIDIA GPU worker, and a development
PostgreSQL StatefulSet. The GPU worker requests one extended `nvidia.com/gpu` resource and relies on
the NVIDIA device plugin to inject a healthy device and `nvidia-smi` support. AgentEval then advertises
the discovered device inventory and applies its own per-device memory and compute-capability admission.

Create the database secret before applying the base:

```bash
cp deploy/kubernetes/secret.example.yaml /tmp/aecontrol-secret.yaml
# Replace both occurrences of replace-me, then:
kubectl apply -f /tmp/aecontrol-secret.yaml
kubectl apply -k deploy/kubernetes
kubectl -n aecontrol rollout status deployment/api
kubectl -n aecontrol port-forward service/api 8000:8000
```

The default image is `ghcr.io/jeremydemers/agent-eval-control-plane:0.17.0`. Tagged releases publish
multi-layer OCI images with an SBOM and build provenance. Override the image in an environment overlay
when promoting by digest.

The included PostgreSQL instance is for portfolio and development clusters. Production deployments
should use a managed PostgreSQL service, external secret management, network policies, TLS ingress,
autoscaling, and a dedicated storage class. GPU nodes must have NVIDIA drivers and the NVIDIA device
plugin installed; the manifests do not install cluster-level GPU operators.
