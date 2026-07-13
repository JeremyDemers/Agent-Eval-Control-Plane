from __future__ import annotations

from unittest.mock import Mock

import pytest

from aecontrol.guardrails import GuardrailsClient, GuardrailsError


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
