from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from aecontrol.guardrails import (
    ExpectedGuardrailAction,
    GuardrailConfigVersion,
    GuardrailEvidence,
    GuardrailsClient,
    GuardrailsError,
    StoredGuardrailEvidence,
    build_guardrail_efficacy_report,
    guardrail_bundle_digest,
)


class StubGuardrailsClient(GuardrailsClient):
    def _request(self, method, path, body):  # type: ignore[no-untyped-def]
        if path == "/rails/configs":
            return [{"id": "content_safety"}, {"id": "jailbreak_detection"}]
        submitted = body["messages"][-1]["content"]
        response_text = "I cannot help with that." if "unsafe" in submitted else submitted
        return {
            "model": body["model"],
            "choices": [{"message": {"content": response_text}}],
            "guardrails": {
                "log": {
                    "activated_rails": [{"type": "output", "name": "content safety"}],
                    "stats": {"total_time": 0.1},
                }
            },
        }


@pytest.mark.asyncio
async def test_guardrails_discovers_configs_and_records_pass_through() -> None:
    client = StubGuardrailsClient()
    assert [item.id for item in await client.configs()] == [
        "content_safety",
        "jailbreak_detection",
    ]
    evidence = await client.check("meta/llama", "content_safety", "question", "safe answer")
    assert evidence.passed_through is True
    assert evidence.response_text == "safe answer"
    assert evidence.activated_rails[0]["name"] == "content safety"
    assert evidence.stats == {"total_time": 0.1}


@pytest.mark.asyncio
async def test_guardrails_records_intervention_without_matching_refusal_phrase() -> None:
    evidence = await StubGuardrailsClient().check(
        "meta/llama", "content_safety", "question", "unsafe answer"
    )
    assert evidence.passed_through is False
    assert evidence.submitted_text == "unsafe answer"
    assert evidence.response_text != evidence.submitted_text


@pytest.mark.asyncio
async def test_guardrails_rejects_invalid_protocol_payloads() -> None:
    class InvalidClient(StubGuardrailsClient):
        def _request(self, method, path, body):  # type: ignore[no-untyped-def]
            return {"choices": []}

    with pytest.raises(GuardrailsError, match="invalid chat completion"):
        await InvalidClient().check("model", "config", "input")


def test_guardrails_transport_omits_or_sends_optional_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = Mock()
    response.read.return_value = b"[]"
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=None)
    opened = Mock(return_value=response)
    monkeypatch.setattr("aecontrol.guardrails.urlopen", opened)

    GuardrailsClient(base_url="http://rails/v1")._request("GET", "/rails/configs", None)
    assert "Authorization" not in opened.call_args.args[0].headers
    GuardrailsClient(base_url="http://rails/v1", api_key="secret")._request(
        "GET", "/rails/configs", None
    )
    assert opened.call_args.args[0].headers["Authorization"] == "Bearer secret"


def test_guardrail_config_versions_validate_immutable_identity() -> None:
    config = GuardrailConfigVersion(
        config_id="system/content-safety",
        version="2026.07.1",
        bundle_sha256="a" * 64,
        created_by="release-bot",
    )

    assert config.active is False
    with pytest.raises(ValidationError):
        GuardrailConfigVersion(
            config_id="content_safety",
            version="invalid version",
            bundle_sha256="not-a-digest",
            created_by="release-bot",
        )


def test_guardrail_bundle_digest_covers_paths_and_content(tmp_path) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "config"
    rails = config / "rails"
    rails.mkdir(parents=True)
    (config / "config.yml").write_text("rails: {}\n")
    (rails / "input.co").write_text("flow check input\n")

    first = guardrail_bundle_digest(config)
    assert first == guardrail_bundle_digest(config)

    (rails / "input.co").write_text("flow check output\n")
    assert guardrail_bundle_digest(config) != first

    (config / "linked.co").symlink_to(rails / "input.co")
    with pytest.raises(ValueError, match="symbolic links"):
        guardrail_bundle_digest(config)


def test_managed_guardrail_evidence_requires_complete_provenance() -> None:
    with pytest.raises(ValidationError, match="version, digest, and activation"):
        GuardrailEvidence(
            config_id="content_safety",
            config_version="2026.07.1",
            model="nim/model",
            submitted_text="input",
            response_text="output",
            passed_through=False,
        )


def test_guardrail_efficacy_report_calculates_confusion_matrix_by_version() -> None:
    def artifact(
        version: str | None,
        passed_through: bool,
        expected_action: ExpectedGuardrailAction | None,
    ) -> StoredGuardrailEvidence:
        return StoredGuardrailEvidence(
            evidence=GuardrailEvidence(
                config_id="content_safety",
                config_version=version,
                config_bundle_sha256="a" * 64 if version else None,
                config_activation_id="00000000-0000-0000-0000-000000000001" if version else None,
                model="nim/model",
                submitted_text="candidate",
                response_text="candidate" if passed_through else "blocked",
                passed_through=passed_through,
                expected_action=expected_action,
            )
        )

    artifacts = [
        artifact("1.0", False, ExpectedGuardrailAction.INTERVENTION),
        artifact("1.0", False, ExpectedGuardrailAction.PASS_THROUGH),
        artifact("1.0", True, ExpectedGuardrailAction.PASS_THROUGH),
        artifact("1.0", True, ExpectedGuardrailAction.INTERVENTION),
        artifact("1.0", True, None),
        artifact(None, True, None),
    ]
    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = datetime(2026, 8, 1, tzinfo=UTC)

    report = build_guardrail_efficacy_report(
        artifacts, window_start=start, window_end=end, config_id="content_safety"
    )

    assert report.total_checks == 6
    assert report.labeled_checks == 4
    managed = next(item for item in report.versions if item.config_version == "1.0")
    assert (managed.true_positives, managed.false_positives) == (1, 1)
    assert (managed.true_negatives, managed.false_negatives) == (1, 1)
    assert managed.sample_count == 5
    assert managed.label_coverage == pytest.approx(0.8)
    assert managed.intervention_rate == pytest.approx(0.4)
    assert managed.accuracy == pytest.approx(0.5)
    assert managed.precision == pytest.approx(0.5)
    assert managed.recall == pytest.approx(0.5)
    assert managed.false_positive_rate == pytest.approx(0.5)
    unmanaged = next(item for item in report.versions if item.config_version is None)
    assert unmanaged.accuracy is None
    assert unmanaged.precision is None
