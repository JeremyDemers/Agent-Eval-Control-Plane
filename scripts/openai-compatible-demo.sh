#!/usr/bin/env bash
set -euo pipefail

MODEL="${OPENAI_COMPAT_MODEL:-llama3.2:3b}"
AGENT_VERSION="openai/${MODEL}"
SUITE="examples/suites/ollama_smoke.yaml"
POLICY="examples/policies/ollama_smoke_gate.yaml"
DATABASE_URL="${DATABASE_URL:-postgresql://aecontrol@127.0.0.1:55432/aecontrol}"
export DATABASE_URL

mkdir -p reports
uv run aecontrol openai doctor
uv run aecontrol run --suite "${SUITE}" --agent-version baseline \
  --output reports/openai-baseline.json --database-url "${DATABASE_URL}"
uv run aecontrol run --suite "${SUITE}" --agent-version "${AGENT_VERSION}" \
  --output reports/openai-candidate.json --database-url "${DATABASE_URL}"
uv run aecontrol compare --baseline reports/openai-baseline.json \
  --candidate reports/openai-candidate.json --output reports/openai-comparison.json
uv run aecontrol report --comparison reports/openai-comparison.json --policy "${POLICY}" \
  --baseline-run reports/openai-baseline.json --candidate-run reports/openai-candidate.json \
  --output reports/openai-compatible.html

baseline_id="$(jq -r .run_id reports/openai-baseline.json)"
candidate_id="$(jq -r .run_id reports/openai-candidate.json)"
uv run aecontrol store compare --baseline-run-id "${baseline_id}" \
  --candidate-run-id "${candidate_id}" --policy "${POLICY}"
uv run aecontrol worker --worker-id openai-worker --label runtime=openai-compatible --once

if uv run aecontrol gate --comparison reports/openai-comparison.json --policy "${POLICY}"; then
  echo "OpenAI-compatible candidate passed the smoke policy."
else
  echo "OpenAI-compatible candidate was blocked; evidence is in reports/openai-compatible.html."
fi
