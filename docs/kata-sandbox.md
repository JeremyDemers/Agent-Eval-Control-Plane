# Kata RuntimeClass Sandbox

AgentEval can execute each public and hidden candidate test in a separate Kubernetes Job selected by
an explicitly pinned Kata Containers `RuntimeClass`. Unlike the process and Podman backends, this
places candidate code behind a separate guest kernel for every test pod. The long-lived API or worker
remains the trusted controller and never copies its service-account token, model credentials,
database credentials, or signing authority into the candidate VM.

Kubernetes documents `RuntimeClass` as the stable mechanism for selecting a runtime handler and notes
that a missing class or unusable handler leaves the pod in a failed terminal state rather than using
the default runtime. Kata integrates with Kubernetes CRI implementations and creates a VM for a Kata
pod. AgentEval pins both the RuntimeClass name and its handler at controller startup, and every Job
also specifies `runtimeClassName`; there is no fallback to `runc`.

## Cluster Prerequisites

Install and operate Kata Containers on dedicated nodes using the upstream
[Kata installation guidance](https://katacontainers.io/docs/). Confirm hardware virtualization and
the selected hypervisor on each node, configure the CRI handler, and create the RuntimeClass through
a cluster-administrator channel. AgentEval intentionally cannot create, update, or delete
RuntimeClasses.

The excluded `deploy/overlays/kata-sandbox/runtime-class.example.yaml` demonstrates a `kata-qemu`
handler, scheduling label, taint tolerance, and pod overhead. Match its handler and scheduling values
to the actual Kata installation. Kubernetes describes RuntimeClass setup, scheduling, and overhead in
its [RuntimeClass documentation](https://kubernetes.io/docs/concepts/containers/runtime-class/).

The namespace must use a CNI that enforces Kubernetes NetworkPolicy before container execution. Apply
admission policy that prevents modification of AgentEval-created Jobs and requires
`runtimeClassName: kata-qemu`, disabled token mounting, and the hardened container fields for pods
labeled `app.kubernetes.io/name=aecontrol-sandbox`.

## Image Promotion

Promote a minimal Python image by immutable repository digest. Tags and malformed digests are rejected
before the controller contacts Kubernetes:

```bash
podman pull python:3.12-slim
SANDBOX_IMAGE="$(podman image inspect python:3.12-slim \
  --format '{{index .RepoDigests 0}}')"
test -n "$SANDBOX_IMAGE"
```

Replace `REPLACE_WITH_64_HEX_DIGEST` in `deploy/overlays/kata-sandbox/workloads.yaml`. The selected
image needs only Python and the standard library. It receives two immutable ConfigMap files: the
candidate `app.py` and one repository-owned test file.

## Deploy

The overlay creates a dedicated controller ServiceAccount, namespaced Role, RoleBinding, and a
resource-name-restricted ClusterRole for reading only `kata-qemu`. The controller can create and
delete sandbox ConfigMaps, NetworkPolicies, and Jobs and can read Job/pod status and candidate logs.
It cannot read Secrets, exec into pods, mutate RuntimeClasses, access nodes, or manage other workload
types.

```bash
kubectl apply -f deploy/overlays/kata-sandbox/runtime-class.example.yaml
# Replace the image digest and verify the handler before continuing.
kubectl get runtimeclass kata-qemu -o jsonpath='{.handler}{"\n"}'
kubectl apply -k deploy/overlays/kata-sandbox
kubectl -n aecontrol rollout status deployment/api
kubectl -n aecontrol exec deployment/api -- uv run aecontrol doctor
```

`AECONTROL_SANDBOX_KUBERNETES_NAMESPACE` defaults to the mounted service-account namespace file.
The overlay supplies it through the downward API. RuntimeClass name, expected handler, image digest,
startup timeout, and poll interval are explicit configuration. `aecontrol doctor` reports only these
non-secret controls and does not contact the cluster.

## Per-Test Controls

Before creating a Job, AgentEval creates its immutable ConfigMap and a label-specific deny-all ingress
and egress NetworkPolicy. The candidate pod has no service-account token, service-link variables,
host networking, host PID/IPC namespaces, shared process namespace, Linux capabilities, privilege
escalation, or writable root filesystem. It runs as UID/GID 65534 with runtime-default seccomp and a
read-only workspace. Equal CPU, memory, and ephemeral-storage requests and limits produce bounded,
Guaranteed-QoS candidate containers.

Jobs have no retries, a bounded active deadline, a one-second termination grace period, and a cleanup
TTL. AgentEval separately enforces a controller-side startup plus execution deadline and truncates
captured output. Candidate exit codes and logs become ordinary test results. RuntimeClass mismatch,
Kubernetes authorization or transport errors, image failures, invalid pod state, controller deadline,
or cleanup failure are infrastructure errors: durable jobs retry through their existing attempt
budget, while synchronous API execution receives a sanitized HTTP 503.

Cleanup deletes the Job with foreground propagation and waits until its pods are gone before deleting
the NetworkPolicy and ConfigMap. Partial creation rolls back every attempted resource, including a
request whose success response might have been lost. Deletion is idempotent for absent objects, but
any other cleanup failure fails the evaluation closed.

## Trust Boundary

This backend materially strengthens candidate isolation; it does not make the surrounding cluster
untrusted. Cluster administrators, node root, the CRI configuration, RuntimeClass object, hypervisor,
Kata guest kernel and agent, image registry, admission controls, and CNI policy enforcement remain in
the trusted computing base. A Kata or hypervisor escape can still reach the node. Keep the runtime and
guest image patched, dedicate and taint sandbox nodes, restrict controller egress, and monitor unusual
Job creation or RuntimeClass changes.

Candidate Jobs do not request NVIDIA devices. Model inference remains in the trusted worker or remote
NVIDIA NIM endpoint; only generated source and deterministic tests cross into the microVM. This keeps
GPU credentials and devices outside the hostile-code boundary.
