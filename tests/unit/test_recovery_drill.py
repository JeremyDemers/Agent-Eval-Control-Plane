from __future__ import annotations

from datetime import UTC, datetime
from email.message import Message
from pathlib import Path
from typing import Any
from urllib.error import HTTPError

import pytest

from aecontrol.recovery_drill import (
    DRILL_LABEL_SELECTOR,
    MAX_KUBERNETES_RESPONSE_BYTES,
    InClusterKubernetesClient,
    RecoveryDrillConfiguration,
    RecoveryDrillError,
    RecoveryDrillOrchestrator,
)


class FakeKubernetesClient:
    def __init__(self, *, fail_verification: bool = False) -> None:
        self.fail_verification = fail_verification
        self.created_cluster: dict[str, Any] | None = None
        self.created_job: dict[str, Any] | None = None
        self.deleted_clusters: list[str] = []
        self.deleted_jobs: list[str] = []
        self.cluster_reads = 0
        self.job_reads = 0
        self.selector: str | None = None

    def create_cluster(self, _namespace: str, body: dict[str, Any]) -> dict[str, Any]:
        self.created_cluster = body
        return body

    def get_cluster(self, _namespace: str, _name: str) -> dict[str, Any]:
        self.cluster_reads += 1
        if self.cluster_reads == 1:
            return {"status": {"phase": "Setting up primary", "conditions": []}}
        return {"status": {"conditions": [{"type": "Ready", "status": "True"}]}}

    def list_clusters(self, _namespace: str, label_selector: str) -> list[dict[str, Any]]:
        self.selector = label_selector
        return [
            {
                "metadata": {
                    "name": "aecontrol-drill-20260701040000",
                    "creationTimestamp": "2026-07-01T04:00:00Z",
                }
            },
            {
                "metadata": {
                    "name": "aecontrol-drill-20260708040000",
                    "creationTimestamp": "2026-07-08T04:00:00Z",
                }
            },
        ]

    def delete_cluster(self, _namespace: str, name: str) -> None:
        self.deleted_clusters.append(name)

    def create_job(self, _namespace: str, body: dict[str, Any]) -> dict[str, Any]:
        self.created_job = body
        return body

    def get_job(self, _namespace: str, _name: str) -> dict[str, Any]:
        self.job_reads += 1
        if self.fail_verification:
            return {"status": {"conditions": [{"type": "Failed", "status": "True"}]}}
        return {"status": {"succeeded": 1}}

    def delete_job(self, _namespace: str, name: str) -> None:
        self.deleted_jobs.append(name)


def _configuration() -> RecoveryDrillConfiguration:
    return RecoveryDrillConfiguration(
        namespace="aecontrol",
        verifier_image="ghcr.io/example/aecontrol:0.50.0",
        max_failed_drills=2,
    )


def test_recovery_drill_creates_latest_wal_restore_verifies_archives_and_cleans_up() -> None:
    client = FakeKubernetesClient()
    now = datetime(2026, 7, 14, 4, 0, tzinfo=UTC)
    ticks = [0.0]
    orchestrator = RecoveryDrillOrchestrator(
        _configuration(),
        client,
        now=lambda: now,
        monotonic=lambda: ticks[0],
        sleep=lambda seconds: ticks.__setitem__(0, ticks[0] + seconds),
        nonce=lambda: "abc123",
    )

    outcome = orchestrator.run()

    assert outcome.success is True
    assert outcome.drill_id == "aecontrol-drill-20260714040000-abc123"
    assert outcome.report_archived is True
    assert client.selector == DRILL_LABEL_SELECTOR
    assert client.deleted_clusters == [
        "aecontrol-drill-20260701040000",
        outcome.cluster_name,
    ]
    assert client.deleted_jobs == [
        "aecontrol-drill-20260701040000-verify",
        outcome.verification_job,
    ]

    assert client.created_cluster is not None
    cluster_spec = client.created_cluster["spec"]
    assert cluster_spec["instances"] == 1
    assert cluster_spec["bootstrap"] == {"recovery": {"source": "aecontrol-drill-source"}}
    assert "recoveryTarget" not in cluster_spec["bootstrap"]["recovery"]
    assert "plugins" not in cluster_spec
    assert cluster_spec["externalClusters"][0]["plugin"]["parameters"] == {
        "barmanObjectName": "aecontrol-postgres-backup",
        "serverName": "aecontrol-postgres",
    }

    assert client.created_job is not None
    assert client.created_job["spec"]["ttlSecondsAfterFinished"] == 1_209_600
    pod = client.created_job["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert pod["automountServiceAccountToken"] is False
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert "--checkpoint-directory" in container["args"]
    assert "--report-s3" in container["args"]
    environment = {item["name"]: item for item in container["env"]}
    assert environment["DATABASE_URL"]["valueFrom"]["secretKeyRef"]["name"] == (
        f"{outcome.cluster_name}-app"
    )
    assert "AECONTROL_ARTIFACT_ED25519_PRIVATE_KEYS" not in environment
    assert "AECONTROL_ARTIFACT_VAULT_TOKEN" not in environment
    assert environment["AWS_ACCESS_KEY_ID"]["valueFrom"]["secretKeyRef"]["optional"] is True


def test_recovery_drill_preserves_failed_cluster_and_job_for_diagnosis() -> None:
    client = FakeKubernetesClient(fail_verification=True)
    now = datetime(2026, 7, 14, 4, 0, tzinfo=UTC)
    orchestrator = RecoveryDrillOrchestrator(
        _configuration(),
        client,
        now=lambda: now,
        monotonic=lambda: 0.0,
        sleep=lambda _value: None,
        nonce=lambda: "abc123",
    )

    with pytest.raises(RecoveryDrillError, match="verification job failed"):
        orchestrator.run()

    current = "aecontrol-drill-20260714040000-abc123"
    assert current not in client.deleted_clusters
    assert f"{current}-verify" not in client.deleted_jobs


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"namespace": "Invalid_Namespace"}, "namespace must be"),
        ({"verifier_image": "bad image"}, "image reference"),
        ({"cluster_timeout_seconds": 299}, "greater than or equal to 300"),
        ({"max_failed_drills": 11}, "less than or equal to 10"),
    ],
)
def test_recovery_drill_configuration_is_strict_and_bounded(
    updates: dict[str, object], message: str
) -> None:
    options: dict[str, object] = {
        "namespace": "aecontrol",
        "verifier_image": "ghcr.io/example/aecontrol:0.50.0",
        **updates,
    }
    with pytest.raises(ValueError, match=message):
        RecoveryDrillConfiguration.model_validate(options)


def test_recovery_drill_configuration_loads_namespace_and_bounds_from_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace = tmp_path / "namespace"
    namespace.write_text("aecontrol\n")
    monkeypatch.setenv("AECONTROL_KUBERNETES_NAMESPACE_FILE", str(namespace))
    monkeypatch.setenv(
        "AECONTROL_RECOVERY_DRILL_VERIFIER_IMAGE", "ghcr.io/example/aecontrol:0.50.0"
    )
    monkeypatch.setenv("AECONTROL_RECOVERY_DRILL_MAX_FAILED", "3")

    configuration = RecoveryDrillConfiguration.from_environment()

    assert configuration.namespace == "aecontrol"
    assert configuration.max_failed_drills == 3
    assert configuration.cluster_timeout_seconds == 3600


class _Response:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        pass

    def read(self, amount: int) -> bytes:
        assert amount == MAX_KUBERNETES_RESPONSE_BYTES + 1
        return self.payload


def test_in_cluster_client_bounds_responses_and_sanitizes_http_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca_file = tmp_path / "ca.crt"
    ca_file.write_text("test CA")
    monkeypatch.setattr(
        "aecontrol.recovery_drill.ssl.create_default_context", lambda **_kwargs: object()
    )
    captured = {}

    def successful_urlopen(request, **_kwargs):  # type: ignore[no-untyped-def]
        captured["url"] = request.full_url
        captured["authorization"] = request.get_header("Authorization")
        captured["content_type"] = request.get_header("Content-type")
        return _Response(b'{"status":{"succeeded":1}}')

    monkeypatch.setattr("aecontrol.recovery_drill.urlopen", successful_urlopen)
    client = InClusterKubernetesClient("https://kubernetes.default.svc", "token", ca_file)

    job = client.get_job("aecontrol", "drill-verify")

    assert job == {"status": {"succeeded": 1}}
    assert captured["url"].endswith("/apis/batch/v1/namespaces/aecontrol/jobs/drill-verify")
    assert captured["authorization"] == "Bearer token"

    client.patch_cluster("aecontrol", "aecontrol-postgres-secondary", {"spec": {}})
    assert captured["content_type"] == "application/merge-patch+json"

    monkeypatch.setattr(
        "aecontrol.recovery_drill.urlopen",
        lambda *_args, **_kwargs: _Response(b"x" * (MAX_KUBERNETES_RESPONSE_BYTES + 1)),
    )
    with pytest.raises(RecoveryDrillError, match="size limit"):
        client.get_job("aecontrol", "drill-verify")

    def failed_urlopen(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise HTTPError("https://kubernetes.invalid", 403, "secret detail", Message(), None)

    monkeypatch.setattr("aecontrol.recovery_drill.urlopen", failed_urlopen)
    with pytest.raises(RecoveryDrillError, match="HTTP 403") as captured_error:
        client.get_job("aecontrol", "drill-verify")
    assert "secret detail" not in str(captured_error.value)
