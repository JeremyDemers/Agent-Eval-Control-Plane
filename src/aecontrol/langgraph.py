from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Any, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field

from aecontrol.models import (
    AgentInput,
    AgentOutput,
    AgentTrajectory,
    ExecutionError,
    ExecutionStatus,
    JsonValue,
    Message,
    TrajectoryStep,
)
from aecontrol.plugins import ExecutionContext

LANGGRAPH_STREAM_MODES = ["tasks", "updates", "values", "messages", "custom"]


class LangGraphRunnable(Protocol):
    def astream(
        self,
        input: dict[str, Any],  # noqa: A002 - matches LangGraph's public protocol
        config: dict[str, Any] | None = None,
        *,
        stream_mode: list[str],
        subgraphs: bool,
        version: str,
    ) -> AsyncIterator[Any]: ...


class LangGraphOutputMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    final_response: str = "final_response"
    patch: str = "patch"
    modified_files: str = "modified_files"
    public_test_output: str = "public_test_output"
    hidden_test_output: str = "hidden_test_output"
    status: str = "status"
    tool_calls: str = "tool_calls"
    tool_results: str = "tool_results"


class LangGraphCaptureOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_events: int = Field(default=10_000, ge=1, le=100_000)
    max_event_bytes: int = Field(default=1_000_000, ge=1_024, le=10_000_000)
    max_total_bytes: int = Field(default=10_000_000, ge=1_024, le=100_000_000)
    capture_payloads: bool = False
    redacted_keys: frozenset[str] = frozenset(
        {"api_key", "authorization", "password", "secret", "token"}
    )


GraphInputBuilder = Callable[[AgentInput], dict[str, Any]]
GraphConfigBuilder = Callable[[AgentInput], dict[str, Any] | None]


class LangGraphRuntimeAdapter:
    name = "langgraph"

    def __init__(
        self,
        graph: LangGraphRunnable,
        *,
        graph_name: str = "graph",
        input_builder: GraphInputBuilder | None = None,
        config_builder: GraphConfigBuilder | None = None,
        output_mapping: LangGraphOutputMapping | None = None,
        capture: LangGraphCaptureOptions | None = None,
    ) -> None:
        self._graph = graph
        self._graph_name = graph_name
        self._input_builder = input_builder or _default_input
        self._config_builder = config_builder
        self._mapping = output_mapping or LangGraphOutputMapping()
        self._capture = capture or LangGraphCaptureOptions()

    async def execute(self, request: AgentInput, context: ExecutionContext) -> AgentOutput:
        started = time.perf_counter()
        trajectory = AgentTrajectory()
        event_count = 0
        stream_bytes = 0
        subgraphs: set[tuple[str, ...]] = set()
        final_state: dict[str, Any] | None = None
        interrupted = False
        try:
            graph_input = self._input_builder(request)
            graph_config = self._config_builder(request) if self._config_builder else None
            stream = self._graph.astream(
                graph_input,
                config=graph_config,
                stream_mode=LANGGRAPH_STREAM_MODES,
                subgraphs=True,
                version="v2",
            )
            async for raw_part in stream:
                event_count += 1
                if event_count > self._capture.max_events:
                    raise ValueError(
                        f"LangGraph emitted more than {self._capture.max_events} events"
                    )
                part = _stream_part(raw_part)
                event_bytes = _json_size(part)
                if event_bytes > self._capture.max_event_bytes:
                    raise ValueError(
                        f"LangGraph stream event exceeded {self._capture.max_event_bytes} bytes"
                    )
                stream_bytes += event_bytes
                if stream_bytes > self._capture.max_total_bytes:
                    raise ValueError(
                        f"LangGraph stream exceeded {self._capture.max_total_bytes} total bytes"
                    )
                namespace = tuple(str(item) for item in part.get("ns", ()))
                if namespace:
                    subgraphs.add(namespace)
                part_type = str(part.get("type", "unknown"))
                data = part.get("data")
                interrupts = part.get("interrupts", ())
                interrupted = interrupted or bool(interrupts)
                if part_type == "values" and not namespace and isinstance(data, Mapping):
                    final_state = dict(data)
                step = self._trajectory_step(part_type, namespace, data)
                if step is not None:
                    trajectory.steps.append(step)
            if final_state is None:
                raise ValueError("LangGraph did not emit a root values state")
            if interrupted:
                raise RuntimeError("LangGraph execution interrupted before completion")
            output = self._output_from_state(final_state, trajectory, started, context)
        except Exception as error:
            output = self._error_output(error, trajectory, started, context)
        output.runtime_metadata.update(
            {
                "provider": "langgraph",
                "graph": self._graph_name,
                "stream_version": "v2",
                "events": event_count,
                "stream_bytes": stream_bytes,
                "subgraphs": len(subgraphs),
                "payload_capture": self._capture.capture_payloads,
            }
        )
        return output

    def _trajectory_step(
        self, part_type: str, namespace: tuple[str, ...], data: object
    ) -> TrajectoryStep | None:
        if part_type == "tasks" and isinstance(data, Mapping):
            error = data.get("error")
            phase = "finished" if "result" in data or "error" in data else "started"
            if error:
                phase = "error"
            payload: dict[str, JsonValue] = {
                "name": str(data.get("name", "unknown")),
                "phase": phase,
                "namespace": list(namespace),
            }
            if "triggers" in data:
                payload["triggers"] = _json_value(data["triggers"], self._capture.redacted_keys)
            if self._capture.capture_payloads:
                for key in ("input", "result", "error", "interrupts"):
                    if key in data:
                        payload[key] = _json_value(data[key], self._capture.redacted_keys)
            elif isinstance(data.get("result"), Mapping):
                payload["result_keys"] = sorted(str(key) for key in data["result"])
            return TrajectoryStep(kind="graph_node", data=payload)
        if part_type == "messages":
            return TrajectoryStep(
                kind="message",
                data=_message_data(data, namespace, self._capture.redacted_keys),
            )
        if part_type in {"updates", "custom"}:
            payload = {
                "event": part_type,
                "namespace": list(namespace),
            }
            if isinstance(data, Mapping):
                payload["keys"] = sorted(str(key) for key in data)
            if self._capture.capture_payloads:
                payload["payload"] = _json_value(data, self._capture.redacted_keys)
            return TrajectoryStep(kind="graph_event", data=payload)
        return None

    def _output_from_state(
        self,
        state: dict[str, Any],
        trajectory: AgentTrajectory,
        started: float,
        context: ExecutionContext,
    ) -> AgentOutput:
        status_value = state.get(self._mapping.status, ExecutionStatus.PASSED.value)
        try:
            status = ExecutionStatus(str(status_value))
        except ValueError as error:
            raise ValueError(f"invalid LangGraph output status: {status_value!r}") from error
        modified_files = state.get(self._mapping.modified_files, [])
        if not isinstance(modified_files, list) or not all(
            isinstance(item, str) for item in modified_files
        ):
            raise ValueError("LangGraph modified_files output must be a list of strings")
        self._append_tool_steps(state, trajectory)
        trajectory.steps.append(TrajectoryStep(kind="final", data={"status": status.value}))
        trajectory.completed_at = trajectory.steps[-1].timestamp
        return AgentOutput(
            final_response=_message(state.get(self._mapping.final_response)),
            trajectory=trajectory,
            patch=_text(state.get(self._mapping.patch, ""), self._mapping.patch),
            modified_files=modified_files,
            public_test_output=_text(
                state.get(self._mapping.public_test_output, "not provided"),
                self._mapping.public_test_output,
            ),
            hidden_test_output=_text(
                state.get(self._mapping.hidden_test_output, "not provided"),
                self._mapping.hidden_test_output,
            ),
            duration_seconds=time.perf_counter() - started,
            status=status,
            runtime_metadata={"agent_version": context.agent_version},
        )

    def _append_tool_steps(self, state: dict[str, Any], trajectory: AgentTrajectory) -> None:
        tool_calls = state.get(self._mapping.tool_calls, [])
        tool_results = state.get(self._mapping.tool_results, [])
        if not isinstance(tool_calls, list) or not isinstance(tool_results, list):
            raise ValueError("LangGraph tool_calls and tool_results outputs must be lists")
        for item in tool_calls:
            if not isinstance(item, Mapping) or not isinstance(item.get("name"), str):
                raise ValueError("LangGraph tool call outputs require a name")
            arguments = item.get("arguments", {})
            if not isinstance(arguments, Mapping):
                raise ValueError("LangGraph tool call arguments must be a mapping")
            trajectory.steps.append(
                TrajectoryStep(
                    kind="tool_call",
                    data={
                        "name": item["name"],
                        "arguments": _json_value(arguments, self._capture.redacted_keys),
                    },
                )
            )
        for item in tool_results:
            if not isinstance(item, Mapping) or not isinstance(item.get("name"), str):
                raise ValueError("LangGraph tool result outputs require a name")
            trajectory.steps.append(
                TrajectoryStep(
                    kind="tool_result",
                    data={
                        "name": item["name"],
                        "ok": bool(item.get("ok", False)),
                        "output": str(item.get("output", "")),
                    },
                )
            )

    def _error_output(
        self,
        error: Exception,
        trajectory: AgentTrajectory,
        started: float,
        context: ExecutionContext,
    ) -> AgentOutput:
        trajectory.steps.append(
            TrajectoryStep(
                kind="error",
                data={"error_type": type(error).__name__, "message": str(error)},
            )
        )
        trajectory.completed_at = trajectory.steps[-1].timestamp
        return AgentOutput(
            final_response=Message(role="assistant", content="LangGraph execution failed."),
            trajectory=trajectory,
            patch="",
            modified_files=[],
            public_test_output=str(error),
            hidden_test_output="not run",
            duration_seconds=time.perf_counter() - started,
            status=ExecutionStatus.ERROR,
            error=ExecutionError(error_type=type(error).__name__, message=str(error)),
            runtime_metadata={"agent_version": context.agent_version},
        )


def _default_input(request: AgentInput) -> dict[str, Any]:
    return {
        "case_id": request.case_id,
        "messages": [item.model_dump(mode="python") for item in request.messages],
        "variables": request.variables,
        "metadata": request.metadata,
    }


def _stream_part(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("LangGraph v2 stream parts must be mappings")
    part = dict(value)
    if "type" not in part or "data" not in part:
        raise ValueError("LangGraph v2 stream part requires type and data")
    return part


def _message_data(
    value: object, namespace: tuple[str, ...], redacted_keys: frozenset[str]
) -> dict[str, JsonValue]:
    message: object = value
    metadata: object = {}
    if isinstance(value, (list, tuple)) and len(value) == 2:
        message, metadata = value
    serialized = _json_value(message, redacted_keys)
    message_payload = serialized if isinstance(serialized, dict) else {"content": serialized}
    role = message_payload.get("role") or message_payload.get("type") or "assistant"
    role_aliases = {"ai": "assistant", "human": "user"}
    payload: dict[str, JsonValue] = {
        "role": role_aliases.get(str(role), str(role)),
        "content": message_payload.get("content", ""),
        "namespace": list(namespace),
    }
    serialized_metadata = _json_value(metadata, redacted_keys)
    if isinstance(serialized_metadata, dict):
        node = serialized_metadata.get("langgraph_node")
        if node is not None:
            payload["node"] = node
    for key in ("id", "tool_calls", "invalid_tool_calls"):
        if message_payload.get(key):
            payload[key] = message_payload[key]
    return payload


def _message(value: object) -> Message | None:
    if value is None:
        return None
    if isinstance(value, Message):
        return value
    if isinstance(value, str):
        return Message(role="assistant", content=value)
    if isinstance(value, Mapping):
        payload = dict(value)
        role = payload.get("role") or payload.get("type") or "assistant"
        role = {"ai": "assistant", "human": "user"}.get(str(role), str(role))
        return Message(role=cast(Any, role), content=_text(payload.get("content", ""), "content"))
    raise ValueError("LangGraph final_response output must be text or a message mapping")


def _text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"LangGraph {field} output must be text")
    return value


def _json_size(value: object) -> int:
    serialized = _json_value(value, frozenset())
    return len(json.dumps(serialized, ensure_ascii=True, default=str).encode())


def _json_value(value: object, redacted_keys: frozenset[str]) -> JsonValue:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    elif is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]"
            if str(key).lower() in redacted_keys
            else _json_value(item, redacted_keys)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_value(item, redacted_keys) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)
