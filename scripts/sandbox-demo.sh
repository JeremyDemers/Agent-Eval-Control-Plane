#!/usr/bin/env bash
set -euo pipefail

mkdir -p reports
sandbox_image="${AECONTROL_SANDBOX_IMAGE:-$(podman image inspect python:3.12-slim --format '{{index .RepoDigests 0}}')}"
AECONTROL_SANDBOX_BACKEND=podman \
AECONTROL_SANDBOX_IMAGE="$sandbox_image" \
AECONTROL_SANDBOX_REQUIRE_DIGEST=true \
uv run aecontrol run \
  --suite examples/suites/ollama_smoke.yaml \
  --agent-version baseline \
  --output reports/podman-sandbox.json

jq -e 'all(.case_results[]; .status == "passed" and .output.runtime_metadata.sandbox_backend == "podman")' \
  reports/podman-sandbox.json >/dev/null
echo "Podman sandbox: 4/4 cases passed with container provenance."
