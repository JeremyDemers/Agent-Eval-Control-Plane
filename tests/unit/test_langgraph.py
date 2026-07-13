from __future__ import annotations

from pathlib import Path
from typing import Any, TypedDict

import pytest
from langgraph.config import get_stream_writer
from langgraph.graph import END, START, StateGraph

from aecontrol.engine import EvaluationEngine
from aecontrol.langgraph import LangGraphCaptureOptions, LangGraphRuntimeAdapter
from aecontrol.models import AgentInput, DatasetCase, EvaluationSuite, ExecutionStatus
from aecontrol.runtime import RuntimeContext


class GraphState(TypedDict, total=False):
    case: DatasetCase
    final_response: str
    patch: str
    modified_files: list[str]
    public_test_output: str
    hidden_test_output: str
    status: str
    tool_calls: list[dict[str, Any]]
    tool_results: list[dict[str, Any]]


def _compiled_graph():  # type: ignore[no-untyped-def]
    def repair(state: GraphState) -> GraphState:
        writer = get_stream_writer()
        writer({"progress": "repaired", "token": "must-not-leak"})
        case = state["case"]
        return {
            "final_response": f"repaired {case.case_id}",
            "patch": "+ fixed\n",
            "modified_files": list(case.expected_modified_files),
            "public_test_output": "ok",
            "hidden_test_output": "ok",
            "status": "passed",
            "tool_calls": [{"name": "apply_patch", "arguments": {"path": "app.py"}}],
            "tool_results": [{"name": "apply_patch", "ok": True, "output": "applied"}],
        }

    child = (
        StateGraph(GraphState)
        .add_node("repair", repair)
        .add_edge(START, "repair")
        .add_edge("repair", END)
        .compile()
    )
    return (
        StateGraph(GraphState)
        .add_node("worker", child)
        .add_edge(START, "worker")
        .add_edge("worker", END)
        .compile()
    )


def _case() -> DatasetCase:
    return DatasetCase(
        case_id="graph-case",
        title="Graph case",
        slice="graph",
        bug_kind="workflow",
        expected_modified_files=["app.py"],
    )


@pytest.mark.asyncio
async def test_langgraph_runtime_maps_v2_stream_and_redacts_payloads() -> None:
    adapter = LangGraphRuntimeAdapter(
        _compiled_graph(),
        graph_name="repair_graph",
        input_builder=lambda request: {"case": request.variables["case"]},
        capture=LangGraphCaptureOptions(capture_payloads=True),
    )

    output = await adapter.execute(
        AgentInput(case_id="graph-case", variables={"case": _case()}),
        RuntimeContext(agent_version="langgraph/repair-v1"),
    )

    assert output.status == ExecutionStatus.PASSED
    assert output.final_response is not None
    assert output.final_response.content == "repaired graph-case"
    assert output.modified_files == ["app.py"]
    assert any(
        step.kind == "tool_call" and step.data["name"] == "apply_patch"
        for step in output.trajectory.steps
    )
    assert output.runtime_metadata["provider"] == "langgraph"
    assert output.runtime_metadata["stream_version"] == "v2"
    assert output.runtime_metadata["stream_bytes"] > 0
    assert output.runtime_metadata["subgraphs"] >= 1
    nodes = [step for step in output.trajectory.steps if step.kind == "graph_node"]
    assert {step.data["name"] for step in nodes} >= {"worker", "repair"}
    custom = next(
        step
        for step in output.trajectory.steps
        if step.kind == "graph_event" and step.data["event"] == "custom"
    )
    assert custom.data["payload"]["token"] == "[REDACTED]"
    assert output.trajectory.steps[-1].kind == "final"


@pytest.mark.asyncio
async def test_evaluation_engine_accepts_langgraph_runtime() -> None:
    adapter = LangGraphRuntimeAdapter(
        _compiled_graph(),
        input_builder=lambda request: {"case": request.variables["case"]},
    )
    suite = EvaluationSuite(
        name="langgraph-contract",
        dataset_path=str(Path("examples/datasets/coding_repair.jsonl")),
        evaluators=["execution_success", "expected_file_modification"],
        concurrency=4,
    )

    run = await EvaluationEngine(runtime=adapter).run(suite, "langgraph/repair-v1")

    assert len(run.case_results) == 24
    assert all(result.status == ExecutionStatus.PASSED for result in run.case_results)
    assert all(
        all(evaluation.passed for evaluation in result.evaluator_results)
        for result in run.case_results
    )


@pytest.mark.asyncio
async def test_langgraph_runtime_converts_graph_failure_to_error_evidence() -> None:
    def fail(_state: GraphState) -> GraphState:
        raise RuntimeError("graph node failed")

    graph = (
        StateGraph(GraphState)
        .add_node("fail", fail)
        .add_edge(START, "fail")
        .add_edge("fail", END)
        .compile()
    )
    adapter = LangGraphRuntimeAdapter(graph, input_builder=lambda _request: {})

    output = await adapter.execute(
        AgentInput(case_id="failure"), RuntimeContext(agent_version="langgraph/failure")
    )

    assert output.status == ExecutionStatus.ERROR
    assert output.error is not None
    assert output.error.error_type == "RuntimeError"
    assert output.public_test_output == "graph node failed"
    assert output.trajectory.steps[-1].kind == "error"


@pytest.mark.asyncio
async def test_langgraph_runtime_rejects_unbounded_or_invalid_streams() -> None:
    class NoisyGraph:
        async def astream(self, *_args: Any, **_kwargs: Any):  # type: ignore[no-untyped-def]
            for index in range(3):
                yield {"type": "custom", "ns": (), "data": {"index": index}}

    limited = LangGraphRuntimeAdapter(NoisyGraph(), capture=LangGraphCaptureOptions(max_events=2))  # type: ignore[arg-type]
    output = await limited.execute(
        AgentInput(case_id="noisy"), RuntimeContext(agent_version="langgraph/noisy")
    )
    assert output.status == ExecutionStatus.ERROR
    assert output.error is not None
    assert "more than 2 events" in output.error.message

    class InvalidGraph:
        async def astream(self, *_args: Any, **_kwargs: Any):  # type: ignore[no-untyped-def]
            yield ("updates", {})

    invalid = LangGraphRuntimeAdapter(InvalidGraph())  # type: ignore[arg-type]
    invalid_output = await invalid.execute(
        AgentInput(case_id="invalid"), RuntimeContext(agent_version="langgraph/invalid")
    )
    assert invalid_output.status == ExecutionStatus.ERROR
    assert invalid_output.error is not None
    assert "must be mappings" in invalid_output.error.message

    class LargeGraph:
        async def astream(self, *_args: Any, **_kwargs: Any):  # type: ignore[no-untyped-def]
            for _ in range(3):
                yield {"type": "custom", "ns": (), "data": {"value": "x" * 500}}

    large = LangGraphRuntimeAdapter(  # type: ignore[arg-type]
        LargeGraph(),
        capture=LangGraphCaptureOptions(max_total_bytes=1_024),
    )
    large_output = await large.execute(
        AgentInput(case_id="large"), RuntimeContext(agent_version="langgraph/large")
    )
    assert large_output.status == ExecutionStatus.ERROR
    assert large_output.error is not None
    assert "1024 total bytes" in large_output.error.message
