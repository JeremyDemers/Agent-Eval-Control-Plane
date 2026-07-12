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

## Repository Security

`.github/workflows/security.yml` runs three independent controls:

- CodeQL static analysis on pull requests, `main`, and a weekly schedule.
- Dependency review on pull requests, blocking newly introduced moderate-or-higher advisories.
- `pip-audit` against runtime dependencies exported from the frozen `uv.lock` on every event.

Actions are pinned to explicit release tags. The dependency audit excludes the editable project and
development-only tools so its result describes the shipped runtime environment. As of the v0.15.0
post-release audit, no known runtime dependency vulnerabilities were reported.

API suite and policy paths are resolved before use and must remain under `AECONTROL_INPUT_ROOT`, which
defaults to the repository's `examples/` directory. Resolution occurs before the boundary check, so
absolute paths, `..` traversal, and symlinks cannot escape the configured root. The local CLI remains
an operator-trust interface and may intentionally read explicit paths supplied by the same user.
