from __future__ import annotations

import pytest

from aecontrol.models import AgentInput, DatasetCase, ExecutionStatus
from aecontrol.nim import NIMClient, parse_nim_agent_version
from aecontrol.openai_compatible import CompatibleRepair
from aecontrol.runtime import DeterministicCodingRuntime, RuntimeContext
from aecontrol.sandbox import fixed_source


def make_case() -> DatasetCase:
    return DatasetCase(case_id="NIM-01", title="repair", slice="general_python", bug_kind="divide")


class StubNIMClient(NIMClient):
    def _request(self, method, path, body):  # type: ignore[no-untyped-def]
        if path == "/models":
            return {"data": [{"id": "meta/llama-test", "object": "model"}]}
        if path == "/metadata":
            return {"model": "meta/llama-test", "profile": "tensorrt_llm"}
        if path == "/version":
            return {"nim": "2.0.0"}
        return {
            "model": "meta/llama-test",
            "choices": [
                {
                    "message": {"content": '{"source":"def solve(a, b):\\n    return a / b\\n"}'},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 8, "completion_tokens": 6, "total_tokens": 14},
        }


@pytest.mark.asyncio
async def test_nim_discovery_metadata_and_provider_provenance() -> None:
    client = StubNIMClient(base_url="http://nim.local/v1")
    assert (await client.models())[0].id == "meta/llama-test"
    metadata, version = await client.deployment_info()
    assert metadata["profile"] == "tensorrt_llm"
    assert version["nim"] == "2.0.0"
    repair = await client.repair("meta/llama-test", make_case())
    assert repair.metadata["provider"] == "nvidia-nim"
    assert repair.metadata["total_tokens"] == 14


@pytest.mark.asyncio
async def test_runtime_executes_nim_repair() -> None:
    case = make_case()

    class RepairClient(NIMClient):
        async def repair(self, model: str, case: DatasetCase) -> CompatibleRepair:
            return CompatibleRepair(
                source=fixed_source(case), metadata={"provider": "nvidia-nim", "model": model}
            )

    output = await DeterministicCodingRuntime(
        nim_client=RepairClient(base_url="http://nim.local/v1")
    ).execute(
        AgentInput(case_id=case.case_id, variables={"case": case}),
        RuntimeContext(agent_version="nim/meta/llama-test"),
    )
    assert output.status == ExecutionStatus.PASSED
    assert output.runtime_metadata["provider"] == "nvidia-nim"


def test_nim_configuration_and_agent_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("NIM_API_KEY", raising=False)
    with pytest.raises(ValueError, match="NVIDIA_API_KEY"):
        NIMClient()
    self_hosted = NIMClient(base_url="http://nim.local/v1")
    assert self_hosted.api_key == "self-hosted-nim"
    assert parse_nim_agent_version("baseline") is None
    assert parse_nim_agent_version("nim/meta/llama") == "meta/llama"
    with pytest.raises(ValueError, match="model name"):
        parse_nim_agent_version("nim/")


def test_nim_prefers_nvidia_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-secret")
    monkeypatch.setenv("NIM_API_KEY", "fallback-secret")
    client = NIMClient()
    assert client.api_key == "nvapi-secret"
    assert "nvapi-secret" not in repr(client)
