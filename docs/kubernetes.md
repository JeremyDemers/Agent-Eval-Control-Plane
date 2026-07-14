# Kubernetes Deployment

The Kustomize base deploys two API replicas, two CPU workers, one NVIDIA GPU worker, and a development
PostgreSQL StatefulSet. The GPU worker requests one extended `nvidia.com/gpu` resource and relies on
the NVIDIA device plugin to inject a healthy device and `nvidia-smi` support. AgentEval then advertises
the discovered device inventory and applies its own per-device memory and compute-capability admission.

Create the database secret before applying the base:

```bash
cp deploy/kubernetes/secret.example.yaml /tmp/aecontrol-secret.yaml
# Replace every placeholder with an Ed25519 key pair from
# `aecontrol store generate-signing-key --algorithm ed25519`, then:
kubectl apply -f /tmp/aecontrol-secret.yaml
kubectl apply -k deploy/kubernetes
kubectl -n aecontrol rollout status deployment/api
kubectl -n aecontrol port-forward service/api 8000:8000
```

The API and worker pools receive the private signing map and public verification map from the Secret.
During rotation, retain old public keys, add the new private/public pair, change the active key ID, and
restart every signing workload before verifying the store. Independent audit deployments need only
the public map. A production cluster should source private material from an external secret manager
rather than committing it.

For per-test microVM isolation, install Kata Containers through the cluster platform, verify its CRI
handler and dedicated nodes, replace the sandbox image digest, and apply
`deploy/overlays/kata-sandbox`. The overlay gives API/workers narrowly scoped Job-controller RBAC but
does not install or mutate the cluster-scoped runtime. Candidate Jobs receive no controller token or
credentials. See [`kata-sandbox.md`](kata-sandbox.md).

API, CPU worker, full-GPU worker, and MIG worker pods run as non-root with Kubernetes
`RuntimeDefault` seccomp confinement. Every application container disables privilege escalation and
drops all Linux capabilities. Cluster policy should enforce these fields at admission and apply a
tested `Localhost` seccomp or AppArmor profile where the workload threat model requires tighter
syscall controls.

The default image is `ghcr.io/jeremydemers/agent-eval-control-plane:0.53.0`. Tagged releases publish
multi-layer OCI images with an SBOM and build provenance. Override the image in an environment overlay
when promoting by digest.

For remote signing, `deploy/overlays/vault-transit` removes the private-key map from API and worker
pods, mounts an externally managed Vault token Secret read-only, and pins one Transit key version.
Create `aecontrol-vault-token` through Vault Kubernetes auth, an external secret manager, or the
excluded example only in an isolated environment; then patch the Vault address, CA trust, key, and
version before applying the overlay. See [`vault-transit-signing.md`](vault-transit-signing.md).

`deploy/overlays/aws-kms` provides the equivalent private-key-free path using a dedicated
IRSA-ready ServiceAccount and one immutable KMS key ARN. Replace the example role and key ARNs, retain
the public verification map in the existing Secret, and apply the overlay. Runtime IAM needs only
`kms:Sign` on that key with an `ED25519_SHA_512` condition. See
[`aws-kms-signing.md`](aws-kms-signing.md).

`deploy/overlays/aws-bedrock` adds a dedicated CPU worker with `runtime=aws-bedrock` placement and an
IRSA-ready ServiceAccount. Its example IAM policy grants model discovery plus `bedrock:InvokeModel`
on one explicit foundation-model ARN; no static AWS access keys are injected. Replace the role and
model ARN before applying the overlay. See [`aws-bedrock.md`](aws-bedrock.md).

OIDC federation is configured on API pods with non-secret issuer metadata. Keep the static operator
credential in the existing authentication Secret; federated tokens cannot replace bootstrap control:

```bash
kubectl -n aecontrol set env deployment/api \
  AECONTROL_OIDC_ISSUER=https://identity.example/realms/agents \
  AECONTROL_OIDC_AUDIENCE=aecontrol-api \
  AECONTROL_OIDC_JWKS_URL=https://identity.example/realms/agents/protocol/openid-connect/certs
```

Use an egress policy that permits HTTPS only to the configured JWKS host. See
[`identity-federation.md`](identity-federation.md).

For retention-locked checkpoints, bind the API service account to an IAM role and inject only the
bucket location; boto3 obtains short-lived workload credentials through its standard provider chain:

```bash
kubectl -n aecontrol set env deployment/api \
  AECONTROL_CHECKPOINT_S3_BUCKET=agent-eval-evidence \
  AECONTROL_CHECKPOINT_S3_REGION=us-east-1 \
  AECONTROL_CHECKPOINT_S3_PREFIX=control-plane/checkpoints
```

Do not place static AWS credentials in the deployment. The bucket must have Object Lock enabled and
the role must be restricted to the checkpoint prefix. See
[`evidence-checkpoints.md`](evidence-checkpoints.md).

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
can use the repository's three-instance CloudNativePG overlay or a managed PostgreSQL service, plus
external secret management, network policies, TLS ingress, autoscaling, and a dedicated storage
class. GPU nodes must have NVIDIA drivers and the NVIDIA device plugin installed; the manifests do
not install cluster-level GPU operators.

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

The base binds the API and every worker to tenant `default`. Multi-tenant installations should use
environment overlays to patch `AECONTROL_TENANT_ID`, worker labels, API-key configuration, and secrets
for each isolated pool. KEDA scaler queries must establish the matching tenant context before reading
the RLS-protected queue. See [`multi-tenancy.md`](multi-tenancy.md) for the complete contract.

## Highly Available PostgreSQL

The CloudNativePG overlay replaces the development StatefulSet with a three-instance PostgreSQL 17
cluster and rewires the API and workers to the operator-generated application Secret:

```bash
kubectl apply -f /tmp/aecontrol-secret.yaml
kubectl apply -k deploy/overlays/cloudnative-pg
kubectl -n aecontrol wait --for=condition=Ready cluster/aecontrol-postgres --timeout=10m
```

Install CloudNativePG first and review the node, storage, durability, image-promotion, and backup
requirements in [`database.md`](database.md). Clusters with Prometheus Operator installed can apply
`deploy/overlays/cloudnative-pg-monitoring` instead to include an explicit PodMonitor.

For continuous WAL archiving and point-in-time recovery, use the Barman Cloud plugin overlay after
configuring its S3 destination and credentials. The `cloudnative-pg-pitr-monitoring` composition adds
backup age and failure alerts to the database PodMonitor. See [`database.md`](database.md) for the
installation order, restore workflow, and cutover controls.

After the checkpoint-publication pipeline maintains a current signed checkpoint Secret, the optional
`cloudnative-pg-recovery-drill` overlay schedules a weekly isolated restore, read-only verification,
immutable report publication, and bounded cleanup. Its service account is namespaced and cannot read
Secrets, Pods, logs, or unrelated resource types. See
[`recovery-verification.md`](recovery-verification.md) for setup and failure retention.

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
