# Coding Repair Agents

The demo uses three deterministic agent versions:

- `baseline`: applies the expected minimal repair for every case.
- `candidate_regressed`: matches baseline behavior except for two security-sensitive cases where it
  strips input but fails to reject unsafe values.
- `candidate_fixed`: restores the baseline validation behavior.

These versions are implemented in `src/aecontrol/agents.py` so the runtime can treat the agent as a
versioned strategy rather than a hard-coded branch.
