from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections import defaultdict
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

DEFAULT_GUARDRAILS_BASE_URL = "http://127.0.0.1:8000/v1"


def guardrail_bundle_digest(directory: str | Path) -> str:
    root = Path(directory).resolve()
    if not root.is_dir():
        raise ValueError(f"guardrail configuration directory does not exist: {root}")
    if not any((root / name).is_file() for name in ("config.yml", "config.yaml")):
        raise ValueError("guardrail configuration requires config.yml or config.yaml")
    candidates = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
    if any(item.is_symlink() for item in candidates):
        raise ValueError("guardrail configuration bundles cannot contain symbolic links")
    digest = hashlib.sha256()
    for path in (item for item in candidates if item.is_file()):
        relative = path.relative_to(root).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


class GuardrailsError(RuntimeError):
    pass


class GuardrailsConfig(BaseModel):
    id: str


class ExpectedGuardrailAction(StrEnum):
    PASS_THROUGH = "pass_through"
    INTERVENTION = "intervention"


class GuardrailConfigVersion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    config_id: str = Field(min_length=1, max_length=500)
    version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    description: str = Field(default="", max_length=1000)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    created_by: str = Field(min_length=1, max_length=64)
    active: bool = False


class GuardrailConfigActivation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    activation_id: UUID = Field(default_factory=uuid4)
    config_id: str = Field(min_length=1, max_length=500)
    version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    activated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    activated_by: str = Field(min_length=1, max_length=64)


class GuardrailEvidence(BaseModel):
    config_id: str
    model: str
    submitted_text: str
    response_text: str
    passed_through: bool
    expected_action: ExpectedGuardrailAction | None = None
    config_version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    config_bundle_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    config_activation_id: UUID | None = None
    activated_rails: Any = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def managed_provenance_is_complete(self) -> GuardrailEvidence:
        provenance = (
            self.config_version,
            self.config_bundle_sha256,
            self.config_activation_id,
        )
        if any(item is not None for item in provenance) and not all(
            item is not None for item in provenance
        ):
            raise ValueError(
                "managed guardrail provenance must include version, digest, and activation"
            )
        return self


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
    config_version: str | None = None
    expected_action: ExpectedGuardrailAction | None = None


class GuardrailEfficacyMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    config_id: str
    config_version: str | None
    sample_count: int = Field(ge=0)
    labeled_count: int = Field(ge=0)
    pass_through_count: int = Field(ge=0)
    intervention_count: int = Field(ge=0)
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    true_negatives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    label_coverage: float = Field(ge=0, le=1)
    intervention_rate: float = Field(ge=0, le=1)
    accuracy: float | None = Field(default=None, ge=0, le=1)
    precision: float | None = Field(default=None, ge=0, le=1)
    recall: float | None = Field(default=None, ge=0, le=1)
    false_positive_rate: float | None = Field(default=None, ge=0, le=1)


class GuardrailEfficacyReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    window_start: datetime
    window_end: datetime
    config_id: str | None = None
    total_checks: int = Field(ge=0)
    labeled_checks: int = Field(ge=0)
    versions: list[GuardrailEfficacyMetrics]


def build_guardrail_efficacy_report(
    artifacts: list[StoredGuardrailEvidence],
    *,
    window_start: datetime,
    window_end: datetime,
    config_id: str | None = None,
) -> GuardrailEfficacyReport:
    grouped: dict[tuple[str, str | None], list[GuardrailEvidence]] = defaultdict(list)
    for artifact in artifacts:
        grouped[(artifact.evidence.config_id, artifact.evidence.config_version)].append(
            artifact.evidence
        )

    versions: list[GuardrailEfficacyMetrics] = []
    for (group_config_id, config_version), evidence_items in sorted(
        grouped.items(), key=lambda item: (item[0][0], item[0][1] or "")
    ):
        labeled = [item for item in evidence_items if item.expected_action is not None]
        interventions = sum(not item.passed_through for item in evidence_items)
        true_positives = sum(
            not item.passed_through and item.expected_action == ExpectedGuardrailAction.INTERVENTION
            for item in labeled
        )
        false_positives = sum(
            not item.passed_through and item.expected_action == ExpectedGuardrailAction.PASS_THROUGH
            for item in labeled
        )
        true_negatives = sum(
            item.passed_through and item.expected_action == ExpectedGuardrailAction.PASS_THROUGH
            for item in labeled
        )
        false_negatives = sum(
            item.passed_through and item.expected_action == ExpectedGuardrailAction.INTERVENTION
            for item in labeled
        )
        sample_count = len(evidence_items)
        labeled_count = len(labeled)
        versions.append(
            GuardrailEfficacyMetrics(
                config_id=group_config_id,
                config_version=config_version,
                sample_count=sample_count,
                labeled_count=labeled_count,
                pass_through_count=sample_count - interventions,
                intervention_count=interventions,
                true_positives=true_positives,
                false_positives=false_positives,
                true_negatives=true_negatives,
                false_negatives=false_negatives,
                label_coverage=_ratio(labeled_count, sample_count),
                intervention_rate=_ratio(interventions, sample_count),
                accuracy=_optional_ratio(true_positives + true_negatives, labeled_count),
                precision=_optional_ratio(true_positives, true_positives + false_positives),
                recall=_optional_ratio(true_positives, true_positives + false_negatives),
                false_positive_rate=_optional_ratio(
                    false_positives, false_positives + true_negatives
                ),
            )
        )
    return GuardrailEfficacyReport(
        window_start=window_start,
        window_end=window_end,
        config_id=config_id,
        total_checks=len(artifacts),
        labeled_checks=sum(item.labeled_count for item in versions),
        versions=versions,
    )


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _optional_ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


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
