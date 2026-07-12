#!/usr/bin/env bash
set -euo pipefail

MODEL="${OLLAMA_MODEL:-llama3.2:3b}"
AGENT_VERSION="ollama/${MODEL}"
SUITE="examples/suites/ollama_smoke.yaml"
POLICY="examples/policies/ollama_smoke_gate.yaml"
DATABASE_URL="${DATABASE_URL:-postgresql://aecontrol@127.0.0.1:55432/aecontrol}"
export DATABASE_URL

mkdir -p reports
uv run aecontrol ollama doctor
uv run aecontrol run --suite "${SUITE}" --agent-version baseline \
  --output reports/ollama-baseline.json --database-url "${DATABASE_URL}"
uv run aecontrol run --suite "${SUITE}" --agent-version "${AGENT_VERSION}" \
  --output reports/ollama-candidate.json --database-url "${DATABASE_URL}"
uv run aecontrol compare --baseline reports/ollama-baseline.json \
  --candidate reports/ollama-candidate.json --output reports/ollama-comparison.json
uv run aecontrol report --comparison reports/ollama-comparison.json --policy "${POLICY}" \
  --baseline-run reports/ollama-baseline.json --candidate-run reports/ollama-candidate.json \
  --output reports/ollama.html
baseline_id="$(jq -r .run_id reports/ollama-baseline.json)"
candidate_id="$(jq -r .run_id reports/ollama-candidate.json)"
uv run aecontrol store compare --baseline-run-id "${baseline_id}" \
  --candidate-run-id "${candidate_id}" --policy "${POLICY}"
uv run aecontrol worker --worker-id ollama-worker --label runtime=ollama --once

if uv run aecontrol gate --comparison reports/ollama-comparison.json --policy "${POLICY}"; then
  echo "Ollama candidate passed the smoke policy."
else
  echo "Ollama candidate was blocked; regression evidence is available in reports/ollama.html."
fi
