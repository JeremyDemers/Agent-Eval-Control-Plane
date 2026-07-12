# Security Policy

## Supported version

Security fixes are applied to the latest release and the `main` branch. Older portfolio releases are
not maintained as separate support lines.

## Reporting a vulnerability

Please do not open a public issue for suspected vulnerabilities. Submit a private report through
[GitHub Security Advisories](https://github.com/JeremyDemers/Agent-Eval-Control-Plane/security/advisories/new)
with:

- the affected component and version or commit,
- reproduction steps or a minimal proof of concept,
- the expected and observed security boundary,
- potential impact, and
- any suggested mitigation.

You should receive an acknowledgement within three business days. After validation, remediation and
disclosure timing will be coordinated through the private advisory. Good-faith research that avoids
privacy violations, service disruption, credential access, and destructive testing is welcome.

## Scope notes

The default process sandbox is a resource-limited development boundary, not hardened isolation for
hostile multi-tenant code. The rootless Podman backend provides the stronger documented local
boundary. See [`docs/security.md`](docs/security.md) for assumptions and remaining limitations.
