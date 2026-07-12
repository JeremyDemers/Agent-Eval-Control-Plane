from __future__ import annotations

import io
import json
from unittest.mock import Mock
from urllib.error import HTTPError

import pytest

from aecontrol.models import AgentInput, DatasetCase, ExecutionStatus
from aecontrol.openai_compatible import (
    CompatibleRepair,
    OpenAICompatibleClient,
    OpenAICompatibleError,
    parse_openai_agent_version,
)
from aecontrol.runtime import DeterministicCodingRuntime, RuntimeContext
from aecontrol.sandbox import fixed_source


def make_case() -> DatasetCase:
    return DatasetCase(
        case_id="COMPAT-GEN-01",
        title="repair",
        slice="general_python",
        bug_kind="divide",
    )


class StubClient(OpenAICompatibleClient):
    def _request(self, method, path, body):  # type: ignore[no-untyped-def]
        if path == "/models":
            return {"data": [{"id": "test:latest", "object": "model"}]}
        return {
            "model": "test:latest",
            "choices": [
                {
                    "message": {"content": '{"source":"def solve(a, b):\\n    return a / b\\n"}'},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
        }


@pytest.mark.asyncio
async def test_compatible_discovery_and_structured_repair() -> None:
    client = StubClient(base_url="http://localhost/v1")

    assert (await client.models())[0].id == "test:latest"
    repair = await client.repair("test:latest", make_case())
    assert "return a / b" in repair.source
    assert repair.metadata["total_tokens"] == 18
    assert repair.metadata["provider"] == "openai-compatible"


@pytest.mark.asyncio
async def test_runtime_executes_compatible_repair() -> None:
    case = make_case()

    class RepairClient(OpenAICompatibleClient):
        async def repair(self, model: str, case: DatasetCase) -> CompatibleRepair:
            return CompatibleRepair(
                source=fixed_source(case),
                metadata={"provider": "openai-compatible", "model": model},
            )

    output = await DeterministicCodingRuntime(openai_client=RepairClient()).execute(
        AgentInput(case_id=case.case_id, variables={"case": case}),
        RuntimeContext(agent_version="openai/test:latest"),
    )

    assert output.status == ExecutionStatus.PASSED
    assert output.runtime_metadata["provider"] == "openai-compatible"


@pytest.mark.asyncio
async def test_runtime_isolates_compatible_provider_failure() -> None:
    case = make_case()

    class FailedClient(OpenAICompatibleClient):
        async def repair(self, model: str, case: DatasetCase) -> CompatibleRepair:
            raise OpenAICompatibleError("offline")

    output = await DeterministicCodingRuntime(openai_client=FailedClient()).execute(
        AgentInput(case_id=case.case_id, variables={"case": case}),
        RuntimeContext(agent_version="openai/test:latest"),
    )

    assert output.status == ExecutionStatus.ERROR
    assert output.error is not None
    assert output.error.error_type == "OpenAICompatibleError"


def test_openai_agent_version_parser() -> None:
    assert parse_openai_agent_version("baseline") is None
    assert parse_openai_agent_version("openai/model") == "model"
    with pytest.raises(ValueError, match="model name"):
        parse_openai_agent_version("openai/")


@pytest.mark.asyncio
async def test_invalid_compatible_completion_is_rejected() -> None:
    class InvalidClient(StubClient):
        def _request(self, method, path, body):  # type: ignore[no-untyped-def]
            return {"choices": []}

    with pytest.raises(OpenAICompatibleError, match="invalid structured repair"):
        await InvalidClient().repair("test", make_case())


def test_transport_sends_authorization_and_decodes_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = Mock()
    response.read.return_value = b'{"data":[]}'
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=None)
    opened = Mock(return_value=response)
    monkeypatch.setattr("aecontrol.openai_compatible.urlopen", opened)
    client = OpenAICompatibleClient(base_url="http://localhost/v1", api_key="secret")

    assert client._request("GET", "/models", None) == {"data": []}
    request = opened.call_args.args[0]
    assert request.headers["Authorization"] == "Bearer secret"


def test_transport_rejects_provider_errors_and_non_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = HTTPError(
        "http://localhost/v1/models",
        500,
        "failed",
        {},
        io.BytesIO(json.dumps({"error": "failed"}).encode()),
    )
    monkeypatch.setattr("aecontrol.openai_compatible.urlopen", Mock(side_effect=error))
    with pytest.raises(OpenAICompatibleError, match="request failed"):
        OpenAICompatibleClient(base_url="http://localhost/v1")._request("GET", "/models", None)

    response = Mock()
    response.read.return_value = b"[]"
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=None)
    monkeypatch.setattr("aecontrol.openai_compatible.urlopen", Mock(return_value=response))
    with pytest.raises(OpenAICompatibleError, match="non-object"):
        OpenAICompatibleClient(base_url="http://localhost/v1")._request("GET", "/models", None)
