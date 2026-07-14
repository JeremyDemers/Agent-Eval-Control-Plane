import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aecontrol.promotion import (
    PromotionConfiguration,
    PromotionError,
    PromotionOrchestrator,
    parse_promotion_token,
)


def _token_payload(**updates: str) -> dict[str, str]:
    return {
        "latestCheckpointTimelineID": "7",
        "redoWalFile": "000000070000000A000000FE",
        "databaseSystemIdentifier": "7523456789012345678",
        "latestCheckpointREDOLocation": "A/FE000028",
        "timeOfLatestCheckpoint": "2026-07-14 13:52:09 UTC",
        "operatorVersion": "1.30.1",
        **updates,
    }


def _encode(payload: dict[str, Any] | None = None) -> str:
    content = payload if payload is not None else _token_payload()
    return base64.b64encode(json.dumps(content, separators=(",", ":")).encode()).decode()


def _cluster(*, ready: bool = True, system_id: str = "7523456789012345678") -> dict[str, Any]:
    return {
        "metadata": {"name": "aecontrol-postgres-secondary", "resourceVersion": "4815"},
        "spec": {
            "replica": {
                "primary": "aecontrol-postgres",
                "source": "aecontrol-postgres",
            }
        },
        "status": {
            "systemID": system_id,
            "phase": "Cluster in healthy state",
            "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
        },
    }


class FakePromotionClient:
    def __init__(self, raw_token: str, cluster: dict[str, Any] | None = None) -> None:
        self.raw_token = raw_token
        self.cluster = cluster or _cluster()
        self.patch: dict[str, Any] | None = None
        self.reads = 0

    def get_cluster(self, _namespace: str, _name: str) -> dict[str, Any]:
        self.reads += 1
        if self.reads == 1:
            return self.cluster
        promoted = json.loads(json.dumps(self.cluster))
        promoted["spec"]["replica"]["primary"] = "aecontrol-postgres-secondary"
        promoted["status"]["lastPromotionToken"] = self.raw_token
        return promoted

    def patch_cluster(self, _namespace: str, _name: str, body: dict[str, Any]) -> dict[str, Any]:
        self.patch = body
        return body


def _configuration(token_file: Path, **updates: object) -> PromotionConfiguration:
    return PromotionConfiguration.model_validate(
        {
            "namespace": "aecontrol",
            "target_cluster": "aecontrol-postgres-secondary",
            "source_cluster": "aecontrol-postgres",
            "token_file": token_file,
            "expected_operator_version": "1.30.1",
            **updates,
        }
    )


def test_controlled_promotion_validates_and_atomically_patches_target(tmp_path: Path) -> None:
    raw_token = _encode()
    token_file = tmp_path / "promotion-token"
    token_file.write_text(f"{raw_token}\n")
    client = FakePromotionClient(raw_token)
    started = datetime(2026, 7, 14, 14, 0, tzinfo=UTC)
    completed = started + timedelta(seconds=12)
    times = iter((started, completed))

    outcome = PromotionOrchestrator(
        _configuration(token_file),
        client,
        now=lambda: next(times),
        monotonic=lambda: 0.0,
        sleep=lambda _seconds: None,
    ).run()

    assert outcome.success is True
    assert outcome.duration_seconds == 12
    assert outcome.database_system_identifier == "7523456789012345678"
    assert len(outcome.token_sha256) == 64
    assert raw_token not in outcome.model_dump_json()
    assert client.patch == {
        "apiVersion": "postgresql.cnpg.io/v1",
        "kind": "Cluster",
        "metadata": {"resourceVersion": "4815"},
        "spec": {
            "replica": {
                "primary": "aecontrol-postgres-secondary",
                "source": "aecontrol-postgres",
                "promotionToken": raw_token,
            }
        },
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value["spec"]["replica"].update(primary="unexpected"), "expected source"),
        (lambda value: value["spec"]["replica"].update(promotionToken="old"), "already"),
        (lambda value: value["spec"]["replica"].update(minApplyDelay="1h"), "delayed"),
        (lambda value: value["status"].update(systemID="999"), "system identifier"),
        (lambda value: value["status"].update(conditions=[]), "not Ready"),
        (
            lambda value: value["status"].update(switchReplicaClusterStatus={"inProgress": True}),
            "changing replica state",
        ),
    ],
)
def test_promotion_preflight_fails_closed(tmp_path: Path, mutation: Any, message: str) -> None:
    raw_token = _encode()
    token_file = tmp_path / "promotion-token"
    token_file.write_text(raw_token)
    cluster = _cluster()
    mutation(cluster)
    client = FakePromotionClient(raw_token, cluster)

    with pytest.raises(PromotionError, match=message):
        PromotionOrchestrator(_configuration(token_file), client).run()

    assert client.patch is None


@pytest.mark.parametrize(
    ("raw_token", "message"),
    [
        ("not-base64", "base64"),
        (_encode({**_token_payload(), "unexpected": "value"}), "fields"),
        (_encode(_token_payload(redoWalFile="unsafe")), "content"),
        (
            base64.b64encode(
                b'{"latestCheckpointTimelineID":"7","latestCheckpointTimelineID":"8"}'
            ).decode(),
            "duplicate",
        ),
    ],
)
def test_promotion_token_parser_rejects_malformed_tokens(raw_token: str, message: str) -> None:
    with pytest.raises(PromotionError, match=message):
        parse_promotion_token(raw_token)


def test_promotion_configuration_requires_distinct_dns_names_and_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="must differ"):
        _configuration(tmp_path / "token", source_cluster="aecontrol-postgres-secondary")

    monkeypatch.setenv("AECONTROL_PROMOTION_NAMESPACE", "aecontrol")
    with pytest.raises(ValueError, match="TARGET_CLUSTER"):
        PromotionConfiguration.from_environment()


def test_promotion_rejects_operator_version_mismatch_without_patching(tmp_path: Path) -> None:
    raw_token = _encode(_token_payload(operatorVersion="1.29.4"))
    token_file = tmp_path / "promotion-token"
    token_file.write_text(raw_token)
    client = FakePromotionClient(raw_token)

    with pytest.raises(PromotionError, match="operator version"):
        PromotionOrchestrator(_configuration(token_file), client).run()

    assert client.patch is None
