#!/usr/bin/env bash
set -euo pipefail

mkdir -p reports
AECONTROL_SANDBOX_BACKEND=podman uv run aecontrol run \
  --suite examples/suites/ollama_smoke.yaml \
  --agent-version baseline \
  --output reports/podman-sandbox.json

jq -e 'all(.case_results[]; .status == "passed" and .output.runtime_metadata.sandbox_backend == "podman")' \
  reports/podman-sandbox.json >/dev/null
echo "Podman sandbox: 4/4 cases passed with container provenance."
