# Security

The coding runtime validates source size and syntax before execution and rejects direct access to
dangerous imports and dynamic/file-opening builtins. The default process backend uses a temporary
workspace, minimal environment, wall-clock timeout, output truncation, and operating-system limits for
CPU time, address space, file size, open descriptors, and child processes.

The optional rootless Podman backend adds a read-only workspace mount, disabled networking, dropped
Linux capabilities, `no-new-privileges`, an unprivileged UID, and container memory, CPU, and PID
limits. Podman applies its runtime-default seccomp profile unless an operator supplies a custom one.
Select the backend with `AECONTROL_SANDBOX_BACKEND=podman`; each run records the selected backend.

For actively hostile candidate code, `AECONTROL_SANDBOX_BACKEND=kubernetes-runtimeclass` creates one
Kubernetes Job per test under a name-and-handler-pinned Kata RuntimeClass. Every candidate gets a
separate guest kernel, immutable source ConfigMap, deny-all NetworkPolicy, digest-pinned image,
disabled service-account token, read-only root filesystem, non-root identity, dropped capabilities,
seccomp, fixed resources, and bounded deadlines. Foreground cleanup keeps network denial in place
until the pod is gone. See [`kata-sandbox.md`](kata-sandbox.md).

## Production Container Policy

Production workers can fail closed unless the sandbox image uses an exact SHA-256 repository digest:

```bash
podman pull python:3.12-slim
export AECONTROL_SANDBOX_BACKEND=podman
export AECONTROL_SANDBOX_IMAGE="$(podman image inspect python:3.12-slim --format '{{index .RepoDigests 0}}')"
export AECONTROL_SANDBOX_REQUIRE_DIGEST=true
uv run aecontrol doctor
```

The executor always uses `--pull=never`, so a digest-pinned image must already exist in local
container storage. This separates image promotion from untrusted-code execution and prevents a tag
from resolving to new content between evaluations. Invalid references, malformed digest values, and
unpinned images in required mode are rejected before Podman starts.

Operators may layer host-installed kernel policies onto the runtime default:

```bash
export AECONTROL_SANDBOX_SECCOMP_PROFILE=/etc/aecontrol/sandbox-seccomp.json
export AECONTROL_SANDBOX_APPARMOR_PROFILE=aecontrol-sandbox
```

The seccomp value must resolve to a readable regular file. The AppArmor name is syntax checked, and
`unconfined` is explicitly rejected. AgentEval passes these controls as `security-opt` arguments;
the host administrator remains responsible for installing, testing, and updating profiles compatible
with Python and the container runtime. `aecontrol doctor` reports whether digest pinning is required
and whether runtime-default or custom policies are active.

Static validation is defense in depth, not a proof of safety. The process backend shares the host
process boundary and should only be used for trusted deterministic fixtures. Podman remains suitable
for lower-risk model-generated code but shares the host kernel even with digest, namespace,
capability, seccomp, and AppArmor controls. Actively hostile code should use the Kata backend on
dedicated, patched nodes with enforced admission and CNI policy. Cluster administrators, node root,
the hypervisor, Kata guest stack, RuntimeClass, admission controller, and CNI remain trusted.

The API binds to `127.0.0.1` by default and assumes a trusted local operator. Evaluation requests
accept local suite and policy paths, so the service must not be exposed to untrusted networks in this
phase. The repository-owned PostgreSQL cluster uses trust authentication only on its loopback listener;
production deployment requires authenticated database connections, API authorization, request limits,
and a dedicated hardened worker boundary.

## Tenant Boundary

Authenticated tenant identity comes only from the operator-owned API-key configuration or the schema
v15 credential registry. Schema v12 enables and forces PostgreSQL row-level security on every tenant
data table, sets identity locally in each transaction, and uses tenant-aware relational constraints.
Request headers, paths, and payloads cannot select or override a tenant. Tenant admins remain scoped
to their resolved tenant.

Production database roles must be non-superusers without `BYPASSRLS`; PostgreSQL superusers bypass
row-level security even when it is forced. Database credentials, authentication configuration, and
tenant-specific worker environments remain trusted operator assets. The browser and unauthenticated
operational endpoints expose only the deployment's configured default tenant, not a global tenant
inventory. See [`multi-tenancy.md`](multi-tenancy.md) for migration and deployment details.

The schema v15 tenant and credential registries intentionally sit outside RLS because authentication
must resolve a digest before binding tenant context. Only isolated static `operator` credentials can
provision or suspend tenants, while tenant `admin` credentials can rotate keys only in their own
namespace. Suspension fails closed, plaintext dynamic keys are returned once, and transactional
revocation preserves at least one active admin. The application database role can still read stored
digests and remains trusted. See [`tenant-lifecycle.md`](tenant-lifecycle.md).

Schema v17 keeps quota policy in the operator-controlled registry while calculating usage under the
authenticated tenant's forced-RLS context. Submission and lease checks share a tenant-specific
transaction advisory lock with the state transition, preventing concurrent replicas from exceeding
configured limits. Quotas govern control-plane admission; they do not replace NVIDIA device
isolation or terminate work already holding a lease. See [`tenant-quotas.md`](tenant-quotas.md).

OIDC access tokens use an explicit asymmetric algorithm allowlist and require signature, issuer,
audience, expiry, issued-at, subject, tenant, and namespaced scope validation. Unknown algorithms are
rejected before JWKS retrieval; fetches and caches are bounded. Federated subjects are pseudonymized,
the tenant status check remains fail closed, and `operator` authority is never accepted from JWT
claims. See [`identity-federation.md`](identity-federation.md).

## Evidence Boundary

Ed25519 signatures let independent auditors verify artifacts without private signing authority.
Schema v14 additionally chains each tenant's evidence in an append-only ledger and rejects ledger
updates or deletes with a PostgreSQL trigger. Integrity audits compare every ledger envelope to its
source row, so source deletion remains observable.

The application database owner can alter schema objects and remains trusted. An administrator who
disables the trigger can truncate the chain tail unless the head digest has been checkpointed outside
PostgreSQL. See [`artifact-integrity.md`](artifact-integrity.md) and
[`evidence-transparency.md`](evidence-transparency.md) for key and checkpoint boundaries.

Schema v16 publishes signed heads with conditional create semantics and S3 Object Lock compliance
retention. The audit compares those anchors with the live chain and reports privileged tail
truncation. AgentEval does not provision buckets or IAM, and its local filesystem sink remains under
host-administrator control. See [`evidence-checkpoints.md`](evidence-checkpoints.md).

AWS KMS remote signing keeps the active Ed25519 private key non-exportable, pins an immutable key ARN,
uses short-lived workload credentials, and locally verifies each response before commit. It does not
prevent a compromised authorized workload from requesting signatures. See
[`aws-kms-signing.md`](aws-kms-signing.md).

## Repository Security

`.github/workflows/security.yml` runs three independent controls:

- CodeQL static analysis on pull requests, `main`, and a weekly schedule.
- Dependency review on pull requests, blocking newly introduced moderate-or-higher advisories.
- `pip-audit` against runtime dependencies exported from the frozen `uv.lock` on every event.

Actions are pinned to explicit release tags. The dependency audit excludes the editable project and
development-only tools so its result describes the shipped runtime environment. The v0.52.0
release-candidate audit reported no known runtime dependency vulnerabilities.

At startup, the API indexes regular suite and policy files under `AECONTROL_INPUT_ROOT`, which defaults
to the repository's `examples/` directory. Resolved symlinks outside that root are excluded. Requests
select a server-owned path by alias and never construct a filesystem path from user input, so absolute
paths, `..` traversal, and symlink escapes are unavailable. The local CLI remains an operator-trust
interface and may intentionally read explicit paths supplied by the same user.
