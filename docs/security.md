# Security

The coding runtime validates source size and syntax before execution and rejects direct access to
dangerous imports and dynamic/file-opening builtins. The default process backend uses a temporary
workspace, minimal environment, wall-clock timeout, output truncation, and operating-system limits for
CPU time, address space, file size, open descriptors, and child processes.

The optional rootless Podman backend adds a read-only workspace mount, disabled networking, dropped
Linux capabilities, `no-new-privileges`, an unprivileged UID, and container memory, CPU, and PID
limits. Select it with `AECONTROL_SANDBOX_BACKEND=podman`; each run records the selected backend.

Static validation is defense in depth, not a proof of safety. The process backend shares the host
kernel and should only be used for trusted deterministic fixtures. Model-generated or third-party code
should use the Podman backend. A production deployment should additionally use a dedicated worker
node, pinned sandbox image digest, seccomp/AppArmor policy, and stronger VM or microVM isolation.

The API binds to `127.0.0.1` by default and assumes a trusted local operator. Evaluation requests
accept local suite and policy paths, so the service must not be exposed to untrusted networks in this
phase. The repository-owned PostgreSQL cluster uses trust authentication only on its loopback listener;
production deployment requires authenticated database connections, API authorization, request limits,
and a dedicated hardened worker boundary.
