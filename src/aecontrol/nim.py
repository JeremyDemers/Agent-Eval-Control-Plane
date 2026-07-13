from __future__ import annotations

import asyncio
import os
from typing import Any
from urllib.parse import urlparse

from aecontrol.openai_compatible import OpenAICompatibleClient

DEFAULT_NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"


class NIMClient(OpenAICompatibleClient):
    """NVIDIA NIM client for hosted API Catalog and self-hosted deployments."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float = 120,
    ) -> None:
        resolved_url = base_url or os.getenv("NIM_BASE_URL") or DEFAULT_NIM_BASE_URL
        resolved_key = api_key or os.getenv("NVIDIA_API_KEY") or os.getenv("NIM_API_KEY")
        if urlparse(resolved_url).hostname == "integrate.api.nvidia.com" and not resolved_key:
            raise ValueError("NVIDIA_API_KEY is required for the NVIDIA API Catalog endpoint")
        super().__init__(
            resolved_url,
            resolved_key or "self-hosted-nim",
            timeout_seconds,
            provider="nvidia-nim",
        )

    async def deployment_metadata(self) -> dict[str, Any]:
        return await self._async_request("/metadata")

    async def deployment_version(self) -> dict[str, Any]:
        return await self._async_request("/version")

    async def deployment_info(self) -> tuple[dict[str, Any], dict[str, Any]]:
        return await asyncio.gather(self.deployment_metadata(), self.deployment_version())

    async def _async_request(self, path: str) -> dict[str, Any]:
        return await asyncio.to_thread(self._request, "GET", path, None)


def parse_nim_agent_version(agent_version: str) -> str | None:
    prefix = "nim/"
    if not agent_version.startswith(prefix):
        return None
    model = agent_version.removeprefix(prefix).strip()
    if not model:
        raise ValueError("NVIDIA NIM agent version must include a model name")
    return model
