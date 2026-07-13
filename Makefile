.PHONY: setup format lint typecheck test test-unit test-property test-contract test-integration test-e2e package demo sdk-demo sandbox-demo langgraph-demo ollama-demo openai-demo service-demo serve worker db-start db-stop db-status docker-build docker-demo podman-build podman-demo clean

PODMAN_ENV = case "$${XDG_DATA_HOME:-}" in "$$HOME"/snap/code/*/.local/share) unset XDG_DATA_HOME ;; esac;
CONTAINER_ENGINE ?= podman
CONTAINER_RUN_FLAGS ?=
DATABASE_URL ?= postgresql://aecontrol@127.0.0.1:55432/aecontrol
PORT ?= 8000

setup:
	uv sync --extra dev

format:
	uv run ruff format .

lint:
	uv run ruff check .

typecheck:
	uv run mypy

test: db-start
	uv run pytest

test-unit:
	uv run pytest tests/unit

test-property:
	uv run pytest tests/property

test-contract:
	uv run pytest tests/contract

test-integration: db-start
	uv run pytest tests/integration

test-e2e:
	uv run pytest tests/e2e

package:
	./scripts/package-smoke.sh

demo:
	./scripts/demo.sh

sandbox-demo:
	./scripts/sandbox-demo.sh

langgraph-demo:
	uv run --extra langgraph python examples/langgraph_runtime.py

sdk-demo: db-start
	DATABASE_URL=$(DATABASE_URL) ./scripts/sdk-demo.sh

ollama-demo: db-start
	DATABASE_URL=$(DATABASE_URL) ./scripts/ollama-demo.sh

openai-demo: db-start
	DATABASE_URL=$(DATABASE_URL) ./scripts/openai-compatible-demo.sh

service-demo: db-start
	DATABASE_URL=$(DATABASE_URL) ./scripts/service-demo.sh

serve: db-start
	DATABASE_URL=$(DATABASE_URL) uv run aecontrol serve --port $(PORT)

worker: db-start
	DATABASE_URL=$(DATABASE_URL) uv run aecontrol worker

db-start:
	./scripts/postgres.sh start

db-stop:
	./scripts/postgres.sh stop

db-status:
	./scripts/postgres.sh status

docker-build:
	$(PODMAN_ENV) $(CONTAINER_ENGINE) build -t aecontrol:local .

docker-demo:
	$(PODMAN_ENV) $(CONTAINER_ENGINE) run --rm $(CONTAINER_RUN_FLAGS) -v "$$(pwd)/reports:/app/reports:Z" aecontrol:local make demo

podman-build: docker-build

podman-demo: CONTAINER_RUN_FLAGS := --userns=keep-id:uid=10001,gid=10001
podman-demo: docker-demo

clean:
	rm -rf .aecontrol reports dist build htmlcov .coverage
