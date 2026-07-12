# Ollama Evaluation

The optional Ollama adapter exercises a real model without weakening deterministic CI. Agent versions
use `ollama/<model>`, and the included smoke suite covers arithmetic, typing, async, and
security-sensitive repairs.

The local `llama3.2:3b` run on the NVIDIA RTX 5000 Ada produced this result:

| Case | Hidden test | Observed behavior |
| --- | --- | --- |
| Arithmetic | Pass | Corrected division and added a zero check |
| Typing | Fail | Copied a modified visible assertion into `app.py` instead of repairing typing |
| Async | Fail | Added an async fixture but did not await `fetch()` in `solve()` |
| Security | Fail | Added type and length checks but still accepted unsafe delimiters |

The candidate passed 1/4 hidden tests and the policy returned `BLOCK`. This is intentional evidence:
the control plane treats model output as an untrusted candidate, executes it in the same evaluation
pipeline, and reports regressions rather than assuming model-backed changes are improvements.

Each case stores the model name, prompt SHA-256, fixed generation settings, token counts, timing, and
done reason. The prompt includes vulnerable source and visible tests only; hidden tests remain private
to the evaluator. Provider errors become case-level `ERROR` results so one outage does not erase the
rest of a run.
