from __future__ import annotations

import time
from dataclasses import dataclass

from aecontrol.agents import get_coding_agent
from aecontrol.models import (
    AgentInput,
    AgentOutput,
    AgentTrajectory,
    DatasetCase,
    ExecutionError,
    ExecutionStatus,
    Message,
    TrajectoryStep,
)
from aecontrol.ollama import OllamaClient, OllamaError, parse_ollama_agent_version
from aecontrol.sandbox import CodingSandbox


@dataclass(frozen=True)
class RuntimeContext:
    agent_version: str


class DeterministicCodingRuntime:
    name = "deterministic_coding"

    def __init__(
        self,
        sandbox: CodingSandbox | None = None,
        ollama_client: OllamaClient | None = None,
    ) -> None:
        self._sandbox = sandbox or CodingSandbox()
        self._ollama = ollama_client or OllamaClient()

    async def execute(self, request: AgentInput, context: RuntimeContext) -> AgentOutput:
        started = time.perf_counter()
        case = request.variables["case"]
        if not isinstance(case, DatasetCase):
            msg = "deterministic runtime requires DatasetCase in request.variables['case']"
            raise TypeError(msg)
        trajectory = AgentTrajectory()
        trajectory.steps.append(
            TrajectoryStep(
                kind="message", data={"role": "user", "content": f"repair {request.case_id}"}
            )
        )
        runtime_metadata: dict[str, object] = {"provider": "deterministic"}
        model = parse_ollama_agent_version(context.agent_version)
        if model is None:
            agent = get_coding_agent(context.agent_version)
            patched = agent.repair(case)
        else:
            trajectory.steps.append(
                TrajectoryStep(kind="tool_call", data={"name": "model_generate", "model": model})
            )
            try:
                repair = await self._ollama.repair(model, case)
            except (OllamaError, ValueError) as error:
                trajectory.steps.append(
                    TrajectoryStep(
                        kind="error",
                        data={"error_type": type(error).__name__, "message": str(error)},
                    )
                )
                trajectory.completed_at = trajectory.steps[-1].timestamp
                return AgentOutput(
                    final_response=Message(role="assistant", content="Model repair failed."),
                    trajectory=trajectory,
                    patch="",
                    modified_files=[],
                    public_test_output=str(error),
                    hidden_test_output="not run",
                    duration_seconds=time.perf_counter() - started,
                    status=ExecutionStatus.ERROR,
                    error=ExecutionError(error_type=type(error).__name__, message=str(error)),
                    runtime_metadata={"provider": "ollama", "model": model},
                )
            patched = repair.source
            runtime_metadata = repair.metadata
            trajectory.steps.append(
                TrajectoryStep(
                    kind="tool_result",
                    data={"name": "model_generate", "ok": True, "model": model},
                )
            )
        result = self._sandbox.run(case, patched)
        for call in result.tool_calls:
            trajectory.steps.append(
                TrajectoryStep(
                    kind="tool_call", data={"name": call.name, "arguments": call.arguments}
                )
            )
        for tool_result in result.tool_results:
            trajectory.steps.append(
                TrajectoryStep(
                    kind="tool_result",
                    data={
                        "name": tool_result.name,
                        "ok": tool_result.ok,
                        "output": tool_result.output,
                    },
                )
            )
        status = (
            ExecutionStatus.PASSED
            if result.public_passed and result.hidden_passed
            else ExecutionStatus.FAILED
        )
        trajectory.completed_at = trajectory.steps[-1].timestamp
        trajectory.steps.append(TrajectoryStep(kind="final", data={"status": status.value}))
        return AgentOutput(
            final_response=Message(role="assistant", content="Applied candidate repair."),
            trajectory=trajectory,
            patch=result.patch,
            modified_files=result.modified_files,
            public_test_output=result.public_test_output,
            hidden_test_output=result.hidden_test_output,
            duration_seconds=time.perf_counter() - started,
            status=status,
            runtime_metadata=runtime_metadata,
        )
