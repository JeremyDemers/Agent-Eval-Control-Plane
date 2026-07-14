from __future__ import annotations

import asyncio
import hashlib
import os
import re
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict

from aecontrol.models import DatasetCase
from aecontrol.ollama import RepairPayload, repair_prompt

BEDROCK_REGION_ENV = "AECONTROL_BEDROCK_REGION"
BEDROCK_PROFILE_ENV = "AECONTROL_BEDROCK_PROFILE"
BEDROCK_TIMEOUT_ENV = "AECONTROL_BEDROCK_TIMEOUT_SECONDS"
DEFAULT_BEDROCK_REGION = "us-east-1"
_REGION_PATTERN = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*$")
_PROFILE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,127}$")


class BedrockError(RuntimeError):
    """Amazon Bedrock could not produce a trusted structured repair."""


@dataclass(frozen=True)
class BedrockConfiguration:
    region: str = DEFAULT_BEDROCK_REGION
    profile: str | None = None
    timeout_seconds: float = 120

    def __post_init__(self) -> None:
        if _REGION_PATTERN.fullmatch(self.region) is None:
            raise ValueError(f"{BEDROCK_REGION_ENV} must be a valid AWS region")
        if self.profile is not None and _PROFILE_PATTERN.fullmatch(self.profile) is None:
            raise ValueError(f"{BEDROCK_PROFILE_ENV} contains invalid characters")
        if not 1 <= self.timeout_seconds <= 300:
            raise ValueError(f"{BEDROCK_TIMEOUT_ENV} must be between 1 and 300 seconds")


class BedrockModel(BaseModel):
    model_config = ConfigDict(strict=True)

    model_id: str
    model_name: str
    provider_name: str
    input_modalities: list[str]
    output_modalities: list[str]
    inference_types: list[str]
    response_streaming_supported: bool


@dataclass(frozen=True)
class BedrockRepair:
    source: str
    metadata: dict[str, Any]


class BedrockClient:
    def __init__(
        self,
        configuration: BedrockConfiguration | None = None,
        runtime_client: Any | None = None,
        control_client: Any | None = None,
    ) -> None:
        self.configuration = configuration or bedrock_configuration_from_environment()
        if runtime_client is None or control_client is None:
            created_runtime, created_control = self._create_clients()
            runtime_client = runtime_client or created_runtime
            control_client = control_client or created_control
        self._runtime = runtime_client
        self._control = control_client

    def _create_clients(self) -> tuple[Any, Any]:
        try:
            import boto3  # type: ignore[import-untyped]
            from botocore.config import Config  # type: ignore[import-untyped]

            session = boto3.Session(
                profile_name=self.configuration.profile,
                region_name=self.configuration.region,
            )
            client_config = Config(
                connect_timeout=self.configuration.timeout_seconds,
                read_timeout=self.configuration.timeout_seconds,
                retries={"max_attempts": 3, "mode": "standard"},
            )
            return (
                session.client("bedrock-runtime", config=client_config),
                session.client("bedrock", config=client_config),
            )
        except (BotoCoreError, ValueError) as error:
            raise BedrockError("Amazon Bedrock client configuration failed") from error

    async def models(self) -> list[BedrockModel]:
        return await asyncio.to_thread(self._models)

    def _models(self) -> list[BedrockModel]:
        try:
            response = self._control.list_foundation_models(byOutputModality="TEXT")
        except (BotoCoreError, ClientError) as error:
            raise BedrockError("Amazon Bedrock model discovery failed") from error
        if not isinstance(response, dict) or not isinstance(response.get("modelSummaries"), list):
            raise BedrockError("Amazon Bedrock returned an invalid model discovery response")
        try:
            return [
                BedrockModel(
                    model_id=item["modelId"],
                    model_name=item["modelName"],
                    provider_name=item["providerName"],
                    input_modalities=item.get("inputModalities", []),
                    output_modalities=item.get("outputModalities", []),
                    inference_types=item.get("inferenceTypesSupported", []),
                    response_streaming_supported=item.get("responseStreamingSupported", False),
                )
                for item in response["modelSummaries"]
            ]
        except (KeyError, TypeError, ValueError) as error:
            raise BedrockError("Amazon Bedrock returned an invalid model summary") from error

    async def repair(self, model: str, case: DatasetCase) -> BedrockRepair:
        return await asyncio.to_thread(self._repair, model, case)

    def _repair(self, model: str, case: DatasetCase) -> BedrockRepair:
        prompt = repair_prompt(case)
        request = {
            "modelId": model,
            "messages": [{"role": "user", "content": [{"text": prompt}]}],
            "inferenceConfig": {"maxTokens": 512, "temperature": 0},
            "toolConfig": {
                "tools": [
                    {
                        "toolSpec": {
                            "name": "coding_repair",
                            "description": "Return the complete replacement app.py source.",
                            "inputSchema": {"json": RepairPayload.model_json_schema()},
                        }
                    }
                ],
                "toolChoice": {"tool": {"name": "coding_repair"}},
            },
            "requestMetadata": {"application": "aecontrol", "operation": "coding-repair"},
        }
        try:
            response = self._runtime.converse(**request)
        except (BotoCoreError, ClientError) as error:
            raise BedrockError("Amazon Bedrock Converse request failed") from error
        repair = self._parse_repair(response)
        usage = response.get("usage")
        metrics = response.get("metrics")
        response_metadata = response.get("ResponseMetadata")
        usage = usage if isinstance(usage, dict) else {}
        metrics = metrics if isinstance(metrics, dict) else {}
        response_metadata = response_metadata if isinstance(response_metadata, dict) else {}
        return BedrockRepair(
            source=repair.source,
            metadata={
                "provider": "aws-bedrock",
                "model": model,
                "region": self.configuration.region,
                "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                "input_tokens": _nonnegative_integer_or_none(usage.get("inputTokens")),
                "output_tokens": _nonnegative_integer_or_none(usage.get("outputTokens")),
                "total_tokens": _nonnegative_integer_or_none(usage.get("totalTokens")),
                "latency_ms": _nonnegative_integer_or_none(metrics.get("latencyMs")),
                "stop_reason": _string_or_none(response.get("stopReason")),
                "request_id": _string_or_none(response_metadata.get("RequestId")),
                "temperature": 0,
            },
        )

    @staticmethod
    def _parse_repair(response: object) -> RepairPayload:
        if not isinstance(response, dict):
            raise BedrockError("Amazon Bedrock returned a non-object Converse response")
        try:
            content = response["output"]["message"]["content"]
        except (KeyError, TypeError) as error:
            raise BedrockError("Amazon Bedrock returned an invalid Converse response") from error
        if not isinstance(content, list):
            raise BedrockError("Amazon Bedrock returned invalid Converse content")
        tool_inputs = [
            block["toolUse"].get("input")
            for block in content
            if isinstance(block, dict)
            and isinstance(block.get("toolUse"), dict)
            and block["toolUse"].get("name") == "coding_repair"
        ]
        if len(tool_inputs) != 1:
            raise BedrockError(
                "Amazon Bedrock did not return exactly one coding repair tool result"
            )
        try:
            repair = RepairPayload.model_validate(tool_inputs[0])
        except ValueError as error:
            raise BedrockError(
                "Amazon Bedrock returned an invalid coding repair payload"
            ) from error
        if not repair.source.strip():
            raise BedrockError("Amazon Bedrock returned an empty source file")
        return repair


def bedrock_configuration_from_environment() -> BedrockConfiguration:
    region = (
        os.getenv(BEDROCK_REGION_ENV)
        or os.getenv("AWS_REGION")
        or os.getenv("AWS_DEFAULT_REGION")
        or DEFAULT_BEDROCK_REGION
    )
    profile = os.getenv(BEDROCK_PROFILE_ENV) or None
    raw_timeout = os.getenv(BEDROCK_TIMEOUT_ENV, "120")
    try:
        timeout = float(raw_timeout)
    except ValueError as error:
        raise ValueError(f"{BEDROCK_TIMEOUT_ENV} must be a number") from error
    return BedrockConfiguration(region=region, profile=profile, timeout_seconds=timeout)


def _nonnegative_integer_or_none(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def parse_bedrock_agent_version(agent_version: str) -> str | None:
    prefix = "bedrock/"
    if not agent_version.startswith(prefix):
        return None
    model = agent_version.removeprefix(prefix).strip()
    if not model:
        raise ValueError("Amazon Bedrock agent version must include a model ID")
    return model
