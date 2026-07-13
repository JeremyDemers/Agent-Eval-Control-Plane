from __future__ import annotations

import asyncio
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pydantic import BaseModel

from aecontrol.models import DatasetCase
from aecontrol.ollama import RepairPayload, repair_prompt

DEFAULT_BASE_URL = "http://127.0.0.1:11434/v1"


class OpenAICompatibleError(RuntimeError):
    pass


class CompatibleModel(BaseModel):
    id: str
    object: str = "model"


@dataclass(frozen=True)
class CompatibleRepair:
    source: str
    metadata: dict[str, Any]


class OpenAICompatibleClient:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float = 120,
        provider: str = "openai-compatible",
    ) -> None:
        self.base_url = (
            base_url or os.getenv("OPENAI_COMPAT_BASE_URL") or DEFAULT_BASE_URL
        ).rstrip("/")
        self.api_key = api_key or os.getenv("OPENAI_COMPAT_API_KEY") or "ollama"
        self.timeout_seconds = timeout_seconds
        self.provider = provider

    async def models(self) -> list[CompatibleModel]:
        payload = await asyncio.to_thread(self._request, "GET", "/models", None)
        return [CompatibleModel.model_validate(item) for item in payload.get("data", [])]

    async def repair(self, model: str, case: DatasetCase) -> CompatibleRepair:
        prompt = repair_prompt(case)
        body = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "temperature": 0,
            "seed": 42,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "coding_repair",
                    "strict": True,
                    "schema": RepairPayload.model_json_schema(),
                },
            },
        }
        response = await asyncio.to_thread(self._request, "POST", "/chat/completions", body)
        try:
            message = response["choices"][0]["message"]["content"]
            repair = RepairPayload.model_validate_json(message)
        except (KeyError, IndexError, TypeError, ValueError) as error:
            raise OpenAICompatibleError(
                "OpenAI-compatible endpoint returned an invalid structured repair"
            ) from error
        usage = response.get("usage", {})
        return CompatibleRepair(
            source=repair.source,
            metadata={
                "provider": self.provider,
                "model": response.get("model", model),
                "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                "prompt_tokens": usage.get("prompt_tokens"),
                "completion_tokens": usage.get("completion_tokens"),
                "total_tokens": usage.get("total_tokens"),
                "finish_reason": response["choices"][0].get("finish_reason"),
                "temperature": 0,
                "seed": 42,
                "base_url": self.base_url,
            },
        )

    def _request(self, method: str, path: str, body: dict[str, object] | None) -> dict[str, Any]:
        request = Request(  # noqa: S310
            f"{self.base_url}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:  # noqa: S310
                payload = json.loads(response.read())
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
            raise OpenAICompatibleError(f"OpenAI-compatible request failed: {error}") from error
        if not isinstance(payload, dict):
            raise OpenAICompatibleError("OpenAI-compatible endpoint returned a non-object response")
        return payload


def parse_openai_agent_version(agent_version: str) -> str | None:
    prefix = "openai/"
    if not agent_version.startswith(prefix):
        return None
    model = agent_version.removeprefix(prefix).strip()
    if not model:
        raise ValueError("OpenAI-compatible agent version must include a model name")
    return model
