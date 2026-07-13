from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, TypedDict

from langgraph.config import get_stream_writer
from langgraph.graph import END, START, StateGraph

from aecontrol import EvaluationEngine, LangGraphRuntimeAdapter
from aecontrol.agents import get_coding_agent
from aecontrol.engine import load_suite
from aecontrol.models import DatasetCase
from aecontrol.sandbox import CodingSandbox


class RepairState(TypedDict, total=False):
    case: DatasetCase
    plan: str
    final_response: str
    patch: str
    modified_files: list[str]
    public_test_output: str
    hidden_test_output: str
    status: str
    tool_calls: list[dict[str, Any]]
    tool_results: list[dict[str, Any]]


def plan_repair(state: RepairState) -> RepairState:
    case = state["case"]
    get_stream_writer()({"phase": "planning", "case_id": case.case_id})
    return {"plan": f"repair {case.bug_kind} in {case.expected_modified_files}"}


def execute_repair(state: RepairState) -> RepairState:
    case = state["case"]
    source = get_coding_agent("candidate_fixed").repair(case)
    result = CodingSandbox().run(case, source)
    return {
        "final_response": f"Applied graph repair for {case.case_id}",
        "patch": result.patch,
        "modified_files": result.modified_files,
        "public_test_output": result.public_test_output,
        "hidden_test_output": result.hidden_test_output,
        "status": "passed" if result.public_passed and result.hidden_passed else "failed",
        "tool_calls": [
            {"name": item.name, "arguments": item.arguments} for item in result.tool_calls
        ],
        "tool_results": [
            {"name": item.name, "ok": item.ok, "output": item.output}
            for item in result.tool_results
        ],
    }


def build_graph():  # type: ignore[no-untyped-def]
    return (
        StateGraph(RepairState)
        .add_node("plan_repair", plan_repair)
        .add_node("execute_repair", execute_repair)
        .add_edge(START, "plan_repair")
        .add_edge("plan_repair", "execute_repair")
        .add_edge("execute_repair", END)
        .compile()
    )


async def main() -> None:
    runtime = LangGraphRuntimeAdapter(
        build_graph(),
        graph_name="coding_repair",
        input_builder=lambda request: {"case": request.variables["case"]},
    )
    run = await EvaluationEngine(runtime=runtime).run(
        load_suite(Path("examples/suites/ollama_smoke.yaml")),
        "langgraph/coding-repair-v1",
    )
    passed = sum(item.hidden_success for item in run.case_results)
    nodes = sorted(
        {
            str(step.data["name"])
            for result in run.case_results
            for step in result.output.trajectory.steps
            if step.kind == "graph_node"
        }
    )
    print(
        json.dumps(
            {
                "agent_version": run.agent_version,
                "cases": len(run.case_results),
                "hidden_passes": f"{passed}/{len(run.case_results)}",
                "graph_nodes": nodes,
                "providers": sorted(
                    {str(item.output.runtime_metadata["provider"]) for item in run.case_results}
                ),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
