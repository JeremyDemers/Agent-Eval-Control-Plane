# Security

The local coding runtime uses temporary workspaces, path traversal checks, sanitized environment
variables, and constrained tool methods. This is not a hardened isolation boundary for untrusted code.
Container isolation and stronger process controls are roadmap items.

The API binds to `127.0.0.1` by default and assumes a trusted local operator. Evaluation requests
accept local suite and policy paths, so the service must not be exposed to untrusted networks in this
phase. The repository-owned PostgreSQL cluster uses trust authentication only on its loopback listener;
production deployment requires authenticated database connections, API authorization, request limits,
and a hardened worker isolation boundary.
