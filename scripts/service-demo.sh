#!/usr/bin/env bash
set -euo pipefail

DATABASE_URL="${DATABASE_URL:-postgresql://aecontrol@127.0.0.1:55432/aecontrol}"
export DATABASE_URL

./scripts/demo.sh

for run_file in reports/baseline.json reports/regressed.json reports/fixed.json; do
  uv run aecontrol store import-run --run "${run_file}"
done

baseline_id="$(jq -r .run_id reports/baseline.json)"
regressed_id="$(jq -r .run_id reports/regressed.json)"
fixed_id="$(jq -r .run_id reports/fixed.json)"
policy="examples/policies/coding_repair_gate.yaml"

uv run aecontrol store compare --baseline-run-id "${baseline_id}" \
  --candidate-run-id "${regressed_id}" --policy "${policy}"
uv run aecontrol store compare --baseline-run-id "${baseline_id}" \
  --candidate-run-id "${fixed_id}" --policy "${policy}"

uv run aecontrol jobs enqueue --suite examples/suites/coding_repair.yaml \
  --agent-version candidate_fixed --priority 10 --max-attempts 2 \
  --accelerator cpu --label runtime=deterministic
uv run aecontrol worker --worker-id demo-worker --label runtime=deterministic --once

echo "Control-plane data is ready. Run 'make serve' and open http://127.0.0.1:8000"
