from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

DEFAULT_GUARDRAILS_BASE_URL = "http://127.0.0.1:8000/v1"


class GuardrailsError(RuntimeError):
    pass


class GuardrailsConfig(BaseModel):
    id: str


class GuardrailEvidence(BaseModel):
    config_id: str
    model: str
    submitted_text: str
    response_text: str
    passed_through: bool
    activated_rails: Any = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)


class StoredGuardrailEvidence(BaseModel):
    evidence_id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    evidence: GuardrailEvidence


class StoredGuardrailEvidenceSummary(BaseModel):
    evidence_id: UUID
    created_at: datetime
    config_id: str
    model: str
    passed_through: bool


class GuardrailsClient:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float = 120,
    ) -> None:
        self.base_url = (
            base_url or os.getenv("NEMO_GUARDRAILS_BASE_URL") or DEFAULT_GUARDRAILS_BASE_URL
        ).rstrip("/")
        self.api_key = api_key or os.getenv("NEMO_GUARDRAILS_API_KEY")
        self.timeout_seconds = timeout_seconds

    async def configs(self) -> list[GuardrailsConfig]:
        payload = await asyncio.to_thread(self._request, "GET", "/rails/configs", None)
        if not isinstance(payload, list):
            raise GuardrailsError("NeMo Guardrails returned an invalid configuration list")
        return [GuardrailsConfig.model_validate(item) for item in payload]

    async def check(
        self,
        model: str,
        config_id: str,
        input_text: str,
        output_text: str | None = None,
    ) -> GuardrailEvidence:
        messages = [{"role": "user", "content": input_text}]
        if output_text is not None:
            messages.append({"role": "assistant", "content": output_text})
        body = {
            "model": model,
            "messages": messages,
            "stream": False,
            "temperature": 0,
            "guardrails": {
                "config_id": config_id,
                "options": {
                    "rails": {
                        "input": True,
                        "output": True,
                        "dialog": False,
                        "retrieval": False,
                    },
                    "log": {"activated_rails": True, "stats": True},
                },
            },
        }
        raw_payload = await asyncio.to_thread(self._request, "POST", "/chat/completions", body)
        if not isinstance(raw_payload, dict):
            raise GuardrailsError("NeMo Guardrails returned a non-object chat completion")
        payload = raw_payload
        try:
            response_text = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as error:
            raise GuardrailsError("NeMo Guardrails returned an invalid chat completion") from error
        if not isinstance(response_text, str):
            raise GuardrailsError("NeMo Guardrails returned non-text content")
        diagnostics = payload.get("guardrails", {}).get("log", payload.get("log", {}))
        if not isinstance(diagnostics, dict):
            diagnostics = {}
        submitted = output_text if output_text is not None else input_text
        return GuardrailEvidence(
            config_id=config_id,
            model=str(payload.get("model", model)),
            submitted_text=submitted,
            response_text=response_text,
            passed_through=response_text == submitted,
            activated_rails=diagnostics.get("activated_rails", []),
            stats=diagnostics.get("stats", {})
            if isinstance(diagnostics.get("stats", {}), dict)
            else {},
        )

    def _request(
        self, method: str, path: str, body: dict[str, object] | None
    ) -> dict[str, Any] | list[Any]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = Request(  # noqa: S310
            f"{self.base_url}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers=headers,
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:  # noqa: S310
                payload = json.loads(response.read())
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
            raise GuardrailsError(f"NeMo Guardrails request failed: {error}") from error
        if not isinstance(payload, (dict, list)):
            raise GuardrailsError("NeMo Guardrails returned an invalid JSON response")
        return payload
