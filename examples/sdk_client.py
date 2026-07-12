from __future__ import annotations

import argparse
import json

from aecontrol import AgentEvalClient


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8010")
    arguments = parser.parse_args()
    client = AgentEvalClient(arguments.url)

    health = client.health()
    run = client.run_evaluation("examples/suites/ollama_smoke.yaml", "baseline")
    passed = sum(result.hidden_success for result in run.case_results)
    print(
        json.dumps(
            {
                "service": health["status"],
                "run_id": str(run.run_id),
                "agent_version": run.agent_version,
                "hidden_passes": f"{passed}/{len(run.case_results)}",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
