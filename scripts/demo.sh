#!/usr/bin/env bash
set -euo pipefail

mkdir -p reports
uv run aecontrol datasets validate examples/datasets/coding_repair.jsonl
uv run aecontrol suites validate examples/suites/coding_repair.yaml
uv run aecontrol run --suite examples/suites/coding_repair.yaml --agent-version baseline --output reports/baseline.json
uv run aecontrol run --suite examples/suites/coding_repair.yaml --agent-version candidate_regressed --output reports/regressed.json
uv run aecontrol compare --baseline reports/baseline.json --candidate reports/regressed.json --output reports/regressed-comparison.json
uv run aecontrol report --comparison reports/regressed-comparison.json --policy examples/policies/coding_repair_gate.yaml --baseline-run reports/baseline.json --candidate-run reports/regressed.json --output reports/regressed.html
if uv run aecontrol gate --comparison reports/regressed-comparison.json --policy examples/policies/coding_repair_gate.yaml; then
  echo "expected candidate_regressed to be blocked" >&2
  exit 1
fi
uv run aecontrol run --suite examples/suites/coding_repair.yaml --agent-version candidate_fixed --output reports/fixed.json
uv run aecontrol compare --baseline reports/baseline.json --candidate reports/fixed.json --output reports/fixed-comparison.json
uv run aecontrol report --comparison reports/fixed-comparison.json --policy examples/policies/coding_repair_gate.yaml --baseline-run reports/baseline.json --candidate-run reports/fixed.json --output reports/fixed.html
uv run aecontrol gate --comparison reports/fixed-comparison.json --policy examples/policies/coding_repair_gate.yaml
