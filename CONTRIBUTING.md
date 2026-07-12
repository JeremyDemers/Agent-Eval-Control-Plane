# Contributing

Thank you for improving AgentEval Control Plane. Keep changes focused, typed, reproducible, and
grounded in the behavior of the existing control-plane contracts.

## Development setup

Requirements are Python 3.12, `uv`, PostgreSQL, and optionally Podman and `nvidia-smi`.

```bash
uv sync --extra dev
make db-start
uv run aecontrol doctor
```

The project-owned PostgreSQL cluster listens on port `55432` and does not require sudo. Set
`DATABASE_URL` to test against another PostgreSQL instance.

## Validation

Run the same gates used by CI before opening a pull request:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
make demo
make package
```

Changes to isolation should also run `make sandbox-demo`. Provider changes should run their focused
Ollama or OpenAI-compatible demo when the required local model is available. Do not make external
providers mandatory for deterministic CI.

## Change guidelines

- Preserve Pydantic contract compatibility or provide an explicit schema migration.
- Keep scheduler decisions atomic in PostgreSQL; diagnostics are observational only.
- Never expose hidden tests to runtime adapters or model prompts.
- Add adversarial tests for authentication, isolation, scheduling, and artifact-integrity changes.
- Document what was actually verified and avoid claiming compatibility with an untested provider.
- Do not commit generated reports, distributions, local databases, credentials, or model artifacts.

Use conventional, imperative commit subjects such as `Add GPU placement diagnostics`. Pull requests
should explain the behavior, risk, and exact validation evidence.
