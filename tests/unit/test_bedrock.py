from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from aecontrol.bedrock import (
    BEDROCK_PROFILE_ENV,
    BEDROCK_REGION_ENV,
    BEDROCK_TIMEOUT_ENV,
    BedrockClient,
    BedrockConfiguration,
    BedrockError,
    BedrockRepair,
    bedrock_configuration_from_environment,
    parse_bedrock_agent_version,
)
from aecontrol.models import AgentInput, DatasetCase, ExecutionStatus
from aecontrol.runtime import DeterministicCodingRuntime, RuntimeContext
from aecontrol.sandbox import fixed_source

MODEL_ID = "us.anthropic.claude-sonnet-test-v1:0"


def make_case() -> DatasetCase:
    return DatasetCase(
        case_id="BEDROCK-01",
        title="repair",
        slice="general_python",
        bug_kind="divide",
    )


def converse_response(source: str | None = None) -> dict[str, Any]:
    return {
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "toolUse": {
                            "toolUseId": "tool-1",
                            "name": "coding_repair",
                            "input": {"source": source or fixed_source(make_case())},
                        }
                    }
                ],
            }
        },
        "stopReason": "tool_use",
        "usage": {"inputTokens": 101, "outputTokens": 42, "totalTokens": 143},
        "metrics": {"latencyMs": 275},
        "ResponseMetadata": {"RequestId": "request-123", "HTTPStatusCode": 200},
    }


class RuntimeClient:
    def __init__(self, response: object | None = None) -> None:
        self.response = response if response is not None else converse_response()
        self.request: dict[str, object] | None = None

    def converse(self, **request: object) -> object:
        self.request = request
        return self.response


class ControlClient:
    response: object = {
        "modelSummaries": [
            {
                "modelId": MODEL_ID,
                "modelName": "Claude Sonnet Test",
                "providerName": "Anthropic",
                "inputModalities": ["TEXT"],
                "outputModalities": ["TEXT"],
                "inferenceTypesSupported": ["ON_DEMAND"],
                "responseStreamingSupported": True,
            }
        ]
    }

    def list_foundation_models(self, **request: object) -> object:
        assert request == {"byOutputModality": "TEXT"}
        return self.response


def client(runtime: object | None = None, control: object | None = None) -> BedrockClient:
    return BedrockClient(
        BedrockConfiguration(region="us-east-2", profile="portfolio", timeout_seconds=30),
        runtime_client=runtime or RuntimeClient(),
        control_client=control or ControlClient(),
    )


@pytest.mark.asyncio
async def test_converse_forces_schema_tool_and_records_bounded_provenance() -> None:
    runtime = RuntimeClient()
    repair = await client(runtime=runtime).repair(MODEL_ID, make_case())

    assert "return a / b" in repair.source
    assert repair.metadata == {
        "provider": "aws-bedrock",
        "model": MODEL_ID,
        "region": "us-east-2",
        "prompt_sha256": repair.metadata["prompt_sha256"],
        "input_tokens": 101,
        "output_tokens": 42,
        "total_tokens": 143,
        "latency_ms": 275,
        "stop_reason": "tool_use",
        "request_id": "request-123",
        "temperature": 0,
    }
    assert len(repair.metadata["prompt_sha256"]) == 64
    assert "portfolio" not in repr(repair.metadata)
    assert runtime.request is not None
    assert runtime.request["modelId"] == MODEL_ID
    assert runtime.request["inferenceConfig"] == {"maxTokens": 512, "temperature": 0}
    tool_config = runtime.request["toolConfig"]
    assert tool_config["toolChoice"] == {"tool": {"name": "coding_repair"}}
    schema = tool_config["tools"][0]["toolSpec"]["inputSchema"]["json"]
    assert schema["required"] == ["source"]
    assert runtime.request["requestMetadata"] == {
        "application": "aecontrol",
        "operation": "coding-repair",
    }


@pytest.mark.asyncio
async def test_model_discovery_maps_text_model_summaries() -> None:
    models = await client().models()
    assert len(models) == 1
    assert models[0].model_id == MODEL_ID
    assert models[0].provider_name == "Anthropic"
    assert models[0].response_streaming_supported is True


@pytest.mark.parametrize(
    ("response", "message"),
    [
        ([], "non-object"),
        ({}, "invalid Converse response"),
        ({"output": {"message": {"content": {}}}}, "invalid Converse content"),
        ({"output": {"message": {"content": [{"text": "source"}]}}}, "exactly one"),
        (
            {
                "output": {
                    "message": {"content": converse_response()["output"]["message"]["content"] * 2}
                }
            },
            "exactly one",
        ),
        (
            {
                "output": {
                    "message": {
                        "content": [
                            {"toolUse": {"name": "coding_repair", "input": {"wrong": "value"}}}
                        ]
                    }
                }
            },
            "invalid coding repair payload",
        ),
        (converse_response("   "), "empty source"),
    ],
)
def test_converse_rejects_untrusted_structured_responses(response: object, message: str) -> None:
    with pytest.raises(BedrockError, match=message):
        client(runtime=RuntimeClient(response))._repair(MODEL_ID, make_case())


def test_provider_errors_are_sanitized() -> None:
    error = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "credential AKIA-SENSITIVE cannot invoke the secret model",
            }
        },
        "Converse",
    )

    class FailedRuntime:
        @staticmethod
        def converse(**_request: object) -> object:
            raise error

    with pytest.raises(BedrockError, match="Converse request failed") as caught:
        client(runtime=FailedRuntime())._repair(MODEL_ID, make_case())
    assert "AKIA-SENSITIVE" not in str(caught.value)
    assert "AccessDenied" not in str(caught.value)

    class FailedControl:
        @staticmethod
        def list_foundation_models(**_request: object) -> object:
            raise error

    with pytest.raises(BedrockError, match="model discovery failed") as caught:
        client(control=FailedControl())._models()
    assert "secret model" not in str(caught.value)


def test_optional_metadata_is_bounded_to_expected_scalar_types() -> None:
    response = converse_response()
    response["usage"] = {"inputTokens": True, "outputTokens": -1, "totalTokens": "143"}
    response["metrics"] = ["not-an-object"]
    response["stopReason"] = {"unexpected": "object"}
    response["ResponseMetadata"] = {"RequestId": b"not-text"}

    repair = client(runtime=RuntimeClient(response))._repair(MODEL_ID, make_case())

    assert repair.metadata["input_tokens"] is None
    assert repair.metadata["output_tokens"] is None
    assert repair.metadata["total_tokens"] is None
    assert repair.metadata["latency_ms"] is None
    assert repair.metadata["stop_reason"] is None
    assert repair.metadata["request_id"] is None


@pytest.mark.parametrize(
    "response",
    [None, {}, {"modelSummaries": {}}, {"modelSummaries": [{"modelId": MODEL_ID}]}],
)
def test_model_discovery_rejects_invalid_responses(response: object) -> None:
    control = ControlClient()
    control.response = response
    with pytest.raises(BedrockError, match="invalid model"):
        client(control=control)._models()


@pytest.mark.asyncio
async def test_runtime_executes_bedrock_repair_and_isolates_failure() -> None:
    case = make_case()

    class RepairClient(BedrockClient):
        async def repair(self, model: str, case: DatasetCase) -> BedrockRepair:
            return BedrockRepair(
                source=fixed_source(case), metadata={"provider": "aws-bedrock", "model": model}
            )

    successful = await DeterministicCodingRuntime(
        bedrock_client=RepairClient(runtime_client=RuntimeClient(), control_client=ControlClient())
    ).execute(
        AgentInput(case_id=case.case_id, variables={"case": case}),
        RuntimeContext(agent_version=f"bedrock/{MODEL_ID}"),
    )
    assert successful.status == ExecutionStatus.PASSED
    assert successful.runtime_metadata["provider"] == "aws-bedrock"

    class FailedClient(BedrockClient):
        async def repair(self, model: str, case: DatasetCase) -> BedrockRepair:
            raise BedrockError("offline")

    failed = await DeterministicCodingRuntime(
        bedrock_client=FailedClient(runtime_client=RuntimeClient(), control_client=ControlClient())
    ).execute(
        AgentInput(case_id=case.case_id, variables={"case": case}),
        RuntimeContext(agent_version=f"bedrock/{MODEL_ID}"),
    )
    assert failed.status == ExecutionStatus.ERROR
    assert failed.error is not None
    assert failed.error.error_type == "BedrockError"
    assert failed.runtime_metadata == {"provider": "aws-bedrock", "model": MODEL_ID}


def test_configuration_environment_and_agent_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(BEDROCK_REGION_ENV, "us-west-2")
    monkeypatch.setenv(BEDROCK_PROFILE_ENV, "agent-eval")
    monkeypatch.setenv(BEDROCK_TIMEOUT_ENV, "45")
    assert bedrock_configuration_from_environment() == BedrockConfiguration(
        region="us-west-2", profile="agent-eval", timeout_seconds=45
    )
    assert parse_bedrock_agent_version("baseline") is None
    assert parse_bedrock_agent_version(f"bedrock/{MODEL_ID}") == MODEL_ID
    with pytest.raises(ValueError, match="model ID"):
        parse_bedrock_agent_version("bedrock/")
    monkeypatch.setenv(BEDROCK_TIMEOUT_ENV, "not-a-number")
    with pytest.raises(ValueError, match="must be a number"):
        bedrock_configuration_from_environment()


@pytest.mark.parametrize(
    ("configuration", "message"),
    [
        (BedrockConfiguration(region="us-east-1"), None),
        (("not-a-region", None, 120), "valid AWS region"),
        (("us-east-1", "bad profile!", 120), "invalid characters"),
        (("us-east-1", None, 0), "between 1 and 300"),
        (("us-east-1", None, 301), "between 1 and 300"),
    ],
)
def test_configuration_validation(configuration: object, message: str | None) -> None:
    if message is None:
        assert configuration == BedrockConfiguration()
        return
    region, profile, timeout = configuration
    with pytest.raises(ValueError, match=message):
        BedrockConfiguration(region=region, profile=profile, timeout_seconds=timeout)


def test_sdk_clients_use_region_profile_timeouts_and_standard_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {"services": []}

    class Session:
        def __init__(self, **options: object) -> None:
            observed["session"] = options

        def client(self, service: str, **options: object) -> object:
            observed["services"].append((service, options))
            return object()

    monkeypatch.setattr("boto3.Session", Session)
    created = BedrockClient(BedrockConfiguration("us-east-2", "portfolio", 20))
    assert created.configuration.region == "us-east-2"
    assert observed["session"] == {"profile_name": "portfolio", "region_name": "us-east-2"}
    assert [item[0] for item in observed["services"]] == ["bedrock-runtime", "bedrock"]
    config = observed["services"][0][1]["config"]
    assert config.connect_timeout == 20
    assert config.read_timeout == 20
    assert config.retries == {"max_attempts": 3, "mode": "standard"}


def test_sdk_client_configuration_failures_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed_session(**_options: object) -> object:
        raise ValueError("profile contains SECRET-CREDENTIAL-CONTENT")

    monkeypatch.setattr("boto3.Session", failed_session)
    with pytest.raises(BedrockError, match="client configuration failed") as caught:
        BedrockClient(BedrockConfiguration())
    assert "SECRET-CREDENTIAL-CONTENT" not in str(caught.value)
