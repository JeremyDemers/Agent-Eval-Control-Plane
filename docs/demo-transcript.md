# Demo Transcript

Run:

```bash
make demo
```

Expected outcome:

```text
baseline: hidden pass rate 24/24
candidate_regressed: hidden pass rate 22/24
delta=-8.33% regressed=['SEC-01', 'SEC-04']
gate: BLOCK
candidate_fixed: hidden pass rate 24/24
delta=0.00% regressed=[]
gate: PASS
```

The important portfolio story is that the aggregate drop is modest while the
`security_sensitive` slice drops from 100% to 66.67%. The quality gate blocks the release because
critical validation regressions should not be hidden by aggregate performance.

Open `reports/regressed.html` after the demo. It shows:

- the aggregate delta,
- per-slice pass rates,
- regressed case identifiers,
- the candidate patch,
- the hidden-test output explaining the failure,
- the tool trajectory including `read_file`, `search_code`, `apply_patch`, and `run_tests`.

Agent version metadata lives in `examples/agents/coding_repair/versions.yaml`, and the executable
strategy classes live in `src/aecontrol/agents.py`.
