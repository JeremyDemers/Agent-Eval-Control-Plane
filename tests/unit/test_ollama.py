from __future__ import annotations

import pytest

from aecontrol.models import AgentInput, DatasetCase, ExecutionStatus
from aecontrol.ollama import OllamaClient, OllamaError, OllamaRepair, parse_ollama_agent_version
from aecontrol.runtime import DeterministicCodingRuntime, RuntimeContext
from aecontrol.sandbox import fixed_source


def make_case() -> DatasetCase:
    return DatasetCase(
        case_id="OLL-GEN-01",
        title="repair",
        slice="general_python",
        bug_kind="divide",
    )


class StubOllamaClient(OllamaClient):
    def _request(self, method, path, body):  # type: ignore[no-untyped-def]
        if path == "/api/version":
            return {"version": "0.30.6"}
        if path == "/api/tags":
            return {"models": [{"name": "test:latest", "size": 10, "digest": "abc"}]}
        return {
            "model": "test:latest",
            "response": '{"source":"def solve(a, b):\\n    return a / b\\n"}',
            "eval_count": 12,
            "done_reason": "stop",
        }


@pytest.mark.asyncio
async def test_ollama_discovery_and_structured_repair() -> None:
    client = StubOllamaClient()

    assert await client.version() == "0.30.6"
    assert (await client.models())[0].name == "test:latest"
    repair = await client.repair("test:latest", make_case())
    assert "return a / b" in repair.source
    assert repair.metadata["seed"] == 42


@pytest.mark.asyncio
async def test_runtime_executes_ollama_repair_and_records_provenance() -> None:
    case = make_case()

    class RepairClient(OllamaClient):
        async def repair(self, model: str, case: DatasetCase) -> OllamaRepair:
            return OllamaRepair(
                source=fixed_source(case), metadata={"provider": "ollama", "model": model}
            )

    runtime = DeterministicCodingRuntime(ollama_client=RepairClient())
    output = await runtime.execute(
        AgentInput(case_id=case.case_id, variables={"case": case}),
        RuntimeContext(agent_version="ollama/test:latest"),
    )

    assert output.status == ExecutionStatus.PASSED
    assert output.runtime_metadata["provider"] == "ollama"
    assert any(step.data.get("name") == "model_generate" for step in output.trajectory.steps)


@pytest.mark.asyncio
async def test_runtime_turns_provider_failure_into_error_artifact() -> None:
    case = make_case()

    class FailedClient(OllamaClient):
        async def repair(self, model: str, case: DatasetCase) -> OllamaRepair:
            raise OllamaError("offline")

    output = await DeterministicCodingRuntime(ollama_client=FailedClient()).execute(
        AgentInput(case_id=case.case_id, variables={"case": case}),
        RuntimeContext(agent_version="ollama/test:latest"),
    )

    assert output.status == ExecutionStatus.ERROR
    assert output.error is not None
    assert output.error.error_type == "OllamaError"


def test_ollama_agent_version_parser() -> None:
    assert parse_ollama_agent_version("baseline") is None
    assert parse_ollama_agent_version("ollama/llama3.2:3b") == "llama3.2:3b"
    with pytest.raises(ValueError, match="model name"):
        parse_ollama_agent_version("ollama/")


@pytest.mark.asyncio
async def test_invalid_structured_repair_is_rejected() -> None:
    class InvalidClient(StubOllamaClient):
        def _request(self, method, path, body):  # type: ignore[no-untyped-def]
            return {"response": "not-json"}

    with pytest.raises(OllamaError, match="invalid structured repair"):
        await InvalidClient().repair("test:latest", make_case())


def test_transport_decodes_objects_and_rejects_other_json(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class Response:
        def __init__(self, payload: bytes) -> None:
            self.payload = payload

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self) -> bytes:
            return self.payload

    monkeypatch.setattr(
        "aecontrol.ollama.urlopen", lambda *_args, **_kwargs: Response(b'{"ok":true}')
    )
    assert OllamaClient()._request("GET", "/health", None) == {"ok": True}

    monkeypatch.setattr("aecontrol.ollama.urlopen", lambda *_args, **_kwargs: Response(b"[]"))
    with pytest.raises(OllamaError, match="non-object"):
        OllamaClient()._request("GET", "/health", None)

    monkeypatch.setattr("aecontrol.ollama.urlopen", lambda *_args, **_kwargs: Response(b"not-json"))
    with pytest.raises(OllamaError, match="request failed"):
        OllamaClient()._request("GET", "/health", None)
