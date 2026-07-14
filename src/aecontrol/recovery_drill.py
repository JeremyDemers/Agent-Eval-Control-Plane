from __future__ import annotations

import json
import os
import re
import ssl
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

KUBERNETES_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
MAX_KUBERNETES_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_SERVICE_ACCOUNT_TOKEN_BYTES = 32 * 1024
DRILL_LABEL_SELECTOR = "aecontrol.io/recovery-drill=true"


class RecoveryDrillError(RuntimeError):
    """A scheduled recovery drill could not complete."""


class RecoveryDrillConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    namespace: str
    source_cluster: str = "aecontrol-postgres"
    object_store: str = "aecontrol-postgres-backup"
    checkpoint_secret: str = "aecontrol-recovery-checkpoints"
    verifier_secret: str = "aecontrol-recovery-verifier"
    report_secret: str = "aecontrol-recovery-report-s3"
    verifier_image: str
    postgres_image: str = "ghcr.io/cloudnative-pg/postgresql:17-standard-trixie"
    storage_size: str = Field(default="20Gi", pattern=r"^[1-9][0-9]*(?:Gi|Ti)$")
    wal_storage_size: str = Field(default="5Gi", pattern=r"^[1-9][0-9]*(?:Gi|Ti)$")
    cluster_timeout_seconds: int = Field(default=3600, ge=300, le=14_400)
    verification_timeout_seconds: int = Field(default=1800, ge=60, le=3600)
    poll_seconds: int = Field(default=10, ge=2, le=60)
    max_failed_drills: int = Field(default=2, ge=1, le=10)
    checkpoint_max_age_hours: int = Field(default=168, ge=1, le=720)
    report_retention_days: int = Field(default=90, ge=1, le=3650)

    def model_post_init(self, _context: Any) -> None:
        for name in (
            "namespace",
            "source_cluster",
            "object_store",
            "checkpoint_secret",
            "verifier_secret",
            "report_secret",
        ):
            if not KUBERNETES_DNS_LABEL.fullmatch(str(getattr(self, name))):
                raise ValueError(f"{name.replace('_', ' ')} must be a Kubernetes DNS label")
        for name in ("verifier_image", "postgres_image"):
            value = str(getattr(self, name))
            if not value or any(character.isspace() for character in value):
                raise ValueError(f"{name.replace('_', ' ')} must be a non-empty image reference")

    @classmethod
    def from_environment(cls) -> RecoveryDrillConfiguration:
        namespace = os.getenv("AECONTROL_RECOVERY_DRILL_NAMESPACE") or _read_namespace()
        verifier_image = os.getenv("AECONTROL_RECOVERY_DRILL_VERIFIER_IMAGE")
        if not verifier_image:
            raise ValueError("AECONTROL_RECOVERY_DRILL_VERIFIER_IMAGE is required")
        return cls(
            namespace=namespace,
            source_cluster=os.getenv(
                "AECONTROL_RECOVERY_DRILL_SOURCE_CLUSTER", "aecontrol-postgres"
            ),
            object_store=os.getenv(
                "AECONTROL_RECOVERY_DRILL_OBJECT_STORE", "aecontrol-postgres-backup"
            ),
            checkpoint_secret=os.getenv(
                "AECONTROL_RECOVERY_DRILL_CHECKPOINT_SECRET",
                "aecontrol-recovery-checkpoints",
            ),
            verifier_secret=os.getenv(
                "AECONTROL_RECOVERY_DRILL_VERIFIER_SECRET", "aecontrol-recovery-verifier"
            ),
            report_secret=os.getenv(
                "AECONTROL_RECOVERY_DRILL_REPORT_SECRET", "aecontrol-recovery-report-s3"
            ),
            verifier_image=verifier_image,
            postgres_image=os.getenv(
                "AECONTROL_RECOVERY_DRILL_POSTGRES_IMAGE",
                "ghcr.io/cloudnative-pg/postgresql:17-standard-trixie",
            ),
            storage_size=os.getenv("AECONTROL_RECOVERY_DRILL_STORAGE_SIZE", "20Gi"),
            wal_storage_size=os.getenv("AECONTROL_RECOVERY_DRILL_WAL_STORAGE_SIZE", "5Gi"),
            cluster_timeout_seconds=_bounded_environment_integer(
                "AECONTROL_RECOVERY_DRILL_CLUSTER_TIMEOUT_SECONDS", 3600
            ),
            verification_timeout_seconds=_bounded_environment_integer(
                "AECONTROL_RECOVERY_DRILL_VERIFICATION_TIMEOUT_SECONDS", 1800
            ),
            poll_seconds=_bounded_environment_integer("AECONTROL_RECOVERY_DRILL_POLL_SECONDS", 10),
            max_failed_drills=_bounded_environment_integer(
                "AECONTROL_RECOVERY_DRILL_MAX_FAILED", 2
            ),
            checkpoint_max_age_hours=_bounded_environment_integer(
                "AECONTROL_RECOVERY_DRILL_CHECKPOINT_MAX_AGE_HOURS", 168
            ),
            report_retention_days=_bounded_environment_integer(
                "AECONTROL_RECOVERY_REPORT_RETENTION_DAYS", 90
            ),
        )


class RecoveryDrillOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    drill_id: str
    cluster_name: str
    verification_job: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float = Field(ge=0)
    success: bool
    restored_cluster_deleted: bool
    report_archived: bool


class RecoveryDrillKubernetesClient(Protocol):
    def create_cluster(self, namespace: str, body: dict[str, Any]) -> dict[str, Any]: ...

    def get_cluster(self, namespace: str, name: str) -> dict[str, Any]: ...

    def list_clusters(self, namespace: str, label_selector: str) -> list[dict[str, Any]]: ...

    def delete_cluster(self, namespace: str, name: str) -> None: ...

    def create_job(self, namespace: str, body: dict[str, Any]) -> dict[str, Any]: ...

    def get_job(self, namespace: str, name: str) -> dict[str, Any]: ...

    def delete_job(self, namespace: str, name: str) -> None: ...


class InClusterKubernetesClient:
    def __init__(
        self,
        api_url: str,
        token: str,
        ca_file: Path,
        *,
        timeout_seconds: float = 10,
    ) -> None:
        if not api_url.startswith("https://"):
            raise ValueError("Kubernetes API URL must use HTTPS")
        if not token or len(token.encode()) > MAX_SERVICE_ACCOUNT_TOKEN_BYTES:
            raise ValueError("Kubernetes service-account token is empty or oversized")
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.context = ssl.create_default_context(cafile=str(ca_file))
        self.timeout_seconds = timeout_seconds

    @classmethod
    def from_environment(cls) -> InClusterKubernetesClient:
        host = os.getenv("KUBERNETES_SERVICE_HOST")
        port = os.getenv("KUBERNETES_SERVICE_PORT_HTTPS", "443")
        if not host:
            raise ValueError("KUBERNETES_SERVICE_HOST is required")
        token_path = Path(
            os.getenv(
                "AECONTROL_KUBERNETES_TOKEN_FILE",
                "/var/run/secrets/kubernetes.io/serviceaccount/token",
            )
        )
        ca_path = Path(
            os.getenv(
                "AECONTROL_KUBERNETES_CA_FILE",
                "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            )
        )
        try:
            with token_path.open("rb") as stream:
                raw_token = stream.read(MAX_SERVICE_ACCOUNT_TOKEN_BYTES + 1)
        except OSError as error:
            raise ValueError("Kubernetes service-account token is unavailable") from error
        if len(raw_token) > MAX_SERVICE_ACCOUNT_TOKEN_BYTES:
            raise ValueError("Kubernetes service-account token is oversized")
        try:
            token = raw_token.decode("utf-8").strip()
        except UnicodeDecodeError as error:
            raise ValueError("Kubernetes service-account token is not UTF-8") from error
        try:
            return cls(f"https://{host}:{port}", token, ca_path)
        except OSError as error:
            raise ValueError("Kubernetes service-account CA is unavailable") from error

    def create_cluster(self, namespace: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/apis/postgresql.cnpg.io/v1/namespaces/{quote(namespace)}/clusters",
            body,
        )

    def get_cluster(self, namespace: str, name: str) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/apis/postgresql.cnpg.io/v1/namespaces/{quote(namespace)}/clusters/{quote(name)}",
        )

    def patch_cluster(self, namespace: str, name: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "PATCH",
            f"/apis/postgresql.cnpg.io/v1/namespaces/{quote(namespace)}/clusters/{quote(name)}",
            body,
            content_type="application/merge-patch+json",
        )

    def list_clusters(self, namespace: str, label_selector: str) -> list[dict[str, Any]]:
        query = urlencode({"labelSelector": label_selector})
        response = self._request(
            "GET",
            f"/apis/postgresql.cnpg.io/v1/namespaces/{quote(namespace)}/clusters?{query}",
        )
        items = response.get("items", [])
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            raise RecoveryDrillError("Kubernetes Cluster list response is invalid")
        return items

    def delete_cluster(self, namespace: str, name: str) -> None:
        self._request(
            "DELETE",
            f"/apis/postgresql.cnpg.io/v1/namespaces/{quote(namespace)}/clusters/{quote(name)}",
            {"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground"},
            allow_not_found=True,
        )

    def create_job(self, namespace: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/apis/batch/v1/namespaces/{quote(namespace)}/jobs", body)

    def get_job(self, namespace: str, name: str) -> dict[str, Any]:
        return self._request(
            "GET", f"/apis/batch/v1/namespaces/{quote(namespace)}/jobs/{quote(name)}"
        )

    def delete_job(self, namespace: str, name: str) -> None:
        self._request(
            "DELETE",
            f"/apis/batch/v1/namespaces/{quote(namespace)}/jobs/{quote(name)}",
            {"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground"},
            allow_not_found=True,
        )

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        allow_not_found: bool = False,
        content_type: str = "application/json",
    ) -> dict[str, Any]:
        encoded = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
        request = Request(  # noqa: S310 - base URL is constrained to in-cluster HTTPS.
            f"{self.api_url}{path}",
            data=encoded,
            method=method,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": content_type,
            },
        )
        try:
            with urlopen(  # noqa: S310 - request URL was built from the validated HTTPS base.
                request, context=self.context, timeout=self.timeout_seconds
            ) as response:
                raw = response.read(MAX_KUBERNETES_RESPONSE_BYTES + 1)
        except HTTPError as error:
            if allow_not_found and error.code == 404:
                return {}
            raise RecoveryDrillError(
                f"Kubernetes API request failed with HTTP {error.code}"
            ) from error
        except (TimeoutError, URLError) as error:
            raise RecoveryDrillError("Kubernetes API request failed") from error
        if len(raw) > MAX_KUBERNETES_RESPONSE_BYTES:
            raise RecoveryDrillError("Kubernetes API response exceeded the size limit")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RecoveryDrillError("Kubernetes API returned invalid JSON") from error
        if not isinstance(payload, dict):
            raise RecoveryDrillError("Kubernetes API returned an invalid object")
        return payload


class RecoveryDrillOrchestrator:
    def __init__(
        self,
        configuration: RecoveryDrillConfiguration,
        client: RecoveryDrillKubernetesClient,
        *,
        now: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
        nonce: Callable[[], str] | None = None,
    ) -> None:
        self.configuration = configuration
        self.client = client
        self.now = now or (lambda: datetime.now(UTC))
        self.monotonic = monotonic or time.monotonic
        self.sleep = sleep or time.sleep
        self.nonce = nonce or (lambda: uuid4().hex[:6])

    def run(self) -> RecoveryDrillOutcome:
        started_at = self.now()
        suffix = self.nonce()
        if not re.fullmatch(r"[a-z0-9]{6}", suffix):
            raise RecoveryDrillError("recovery drill nonce is invalid")
        drill_id = f"aecontrol-drill-{started_at.strftime('%Y%m%d%H%M%S').lower()}-{suffix}"
        cluster_name = drill_id
        job_name = f"{drill_id}-verify"
        self._prune_failed_drills()
        self.client.create_cluster(
            self.configuration.namespace, self._cluster_manifest(cluster_name, drill_id)
        )
        try:
            self._wait_for_cluster(cluster_name)
            self.client.create_job(
                self.configuration.namespace,
                self._verification_job_manifest(cluster_name, job_name, drill_id),
            )
            self._wait_for_job(job_name)
        except Exception as error:
            if isinstance(error, RecoveryDrillError):
                raise
            raise RecoveryDrillError("recovery drill orchestration failed") from error

        self.client.delete_job(self.configuration.namespace, job_name)
        self.client.delete_cluster(self.configuration.namespace, cluster_name)
        completed_at = self.now()
        return RecoveryDrillOutcome(
            drill_id=drill_id,
            cluster_name=cluster_name,
            verification_job=job_name,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=max(0.0, (completed_at - started_at).total_seconds()),
            success=True,
            restored_cluster_deleted=True,
            report_archived=True,
        )

    def _prune_failed_drills(self) -> None:
        clusters = self.client.list_clusters(self.configuration.namespace, DRILL_LABEL_SELECTOR)

        def creation_timestamp(item: dict[str, Any]) -> str:
            metadata = item.get("metadata", {})
            return str(metadata.get("creationTimestamp", "")) if isinstance(metadata, dict) else ""

        ordered = sorted(clusters, key=creation_timestamp)
        prune_count = max(0, len(ordered) - self.configuration.max_failed_drills + 1)
        for item in ordered[:prune_count]:
            metadata = item.get("metadata", {})
            if not isinstance(metadata, dict):
                continue
            name = str(metadata.get("name", ""))
            if not KUBERNETES_DNS_LABEL.fullmatch(name):
                continue
            self.client.delete_job(self.configuration.namespace, f"{name}-verify")
            self.client.delete_cluster(self.configuration.namespace, name)

    def _wait_for_cluster(self, name: str) -> None:
        deadline = self.monotonic() + self.configuration.cluster_timeout_seconds
        while self.monotonic() < deadline:
            cluster = self.client.get_cluster(self.configuration.namespace, name)
            status = cluster.get("status", {})
            conditions = status.get("conditions", []) if isinstance(status, dict) else []
            if _condition_true(conditions, "Ready"):
                return
            phase = str(status.get("phase", "")) if isinstance(status, dict) else ""
            if phase.lower() in {"error", "unrecoverable"}:
                raise RecoveryDrillError("recovery cluster entered a terminal failure phase")
            self.sleep(self.configuration.poll_seconds)
        raise RecoveryDrillError("recovery cluster readiness timed out")

    def _wait_for_job(self, name: str) -> None:
        deadline = self.monotonic() + self.configuration.verification_timeout_seconds
        while self.monotonic() < deadline:
            job = self.client.get_job(self.configuration.namespace, name)
            status = job.get("status", {})
            if isinstance(status, dict) and int(status.get("succeeded", 0) or 0) >= 1:
                return
            conditions = status.get("conditions", []) if isinstance(status, dict) else []
            if _condition_true(conditions, "Failed"):
                raise RecoveryDrillError("recovery verification job failed")
            self.sleep(self.configuration.poll_seconds)
        raise RecoveryDrillError("recovery verification job timed out")

    def _cluster_manifest(self, name: str, drill_id: str) -> dict[str, Any]:
        configuration = self.configuration
        return {
            "apiVersion": "postgresql.cnpg.io/v1",
            "kind": "Cluster",
            "metadata": {
                "name": name,
                "namespace": configuration.namespace,
                "labels": {
                    "aecontrol.io/recovery-drill": "true",
                    "aecontrol.io/drill-id": drill_id,
                },
            },
            "spec": {
                "description": "Ephemeral AgentEval scheduled recovery drill",
                "instances": 1,
                "imageName": configuration.postgres_image,
                "enableSuperuserAccess": False,
                "bootstrap": {"recovery": {"source": "aecontrol-drill-source"}},
                "externalClusters": [
                    {
                        "name": "aecontrol-drill-source",
                        "plugin": {
                            "name": "barman-cloud.cloudnative-pg.io",
                            "parameters": {
                                "barmanObjectName": configuration.object_store,
                                "serverName": configuration.source_cluster,
                            },
                        },
                    }
                ],
                "resources": {
                    "requests": {"cpu": "500m", "memory": "1Gi"},
                    "limits": {"cpu": "2", "memory": "4Gi"},
                },
                "storage": {"size": configuration.storage_size},
                "walStorage": {"size": configuration.wal_storage_size},
            },
        }

    def _verification_job_manifest(
        self, cluster_name: str, job_name: str, drill_id: str
    ) -> dict[str, Any]:
        configuration = self.configuration
        secret_env = [
            _secret_environment(
                "AECONTROL_RECOVERY_REPORT_S3_BUCKET", configuration.report_secret, "bucket"
            ),
            _secret_environment(
                "AECONTROL_RECOVERY_REPORT_S3_REGION",
                configuration.report_secret,
                "region",
                optional=True,
            ),
            _secret_environment(
                "AECONTROL_RECOVERY_REPORT_S3_ENDPOINT",
                configuration.report_secret,
                "endpoint",
                optional=True,
            ),
            _secret_environment(
                "AWS_ACCESS_KEY_ID",
                configuration.report_secret,
                "aws-access-key-id",
                optional=True,
            ),
            _secret_environment(
                "AWS_SECRET_ACCESS_KEY",
                configuration.report_secret,
                "aws-secret-access-key",
                optional=True,
            ),
            _secret_environment(
                "AWS_SESSION_TOKEN",
                configuration.report_secret,
                "aws-session-token",
                optional=True,
            ),
        ]
        return {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": job_name,
                "namespace": configuration.namespace,
                "labels": {
                    "aecontrol.io/recovery-drill": "true",
                    "aecontrol.io/drill-id": drill_id,
                },
            },
            "spec": {
                "backoffLimit": 0,
                "activeDeadlineSeconds": configuration.verification_timeout_seconds,
                "ttlSecondsAfterFinished": 1_209_600,
                "template": {
                    "metadata": {
                        "labels": {
                            "aecontrol.io/recovery-drill": "true",
                            "aecontrol.io/drill-id": drill_id,
                        }
                    },
                    "spec": {
                        "automountServiceAccountToken": False,
                        "restartPolicy": "Never",
                        "securityContext": {
                            "runAsNonRoot": True,
                            "seccompProfile": {"type": "RuntimeDefault"},
                        },
                        "containers": [
                            {
                                "name": "verifier",
                                "image": configuration.verifier_image,
                                "imagePullPolicy": "IfNotPresent",
                                "command": ["/app/.venv/bin/aecontrol"],
                                "args": [
                                    "store",
                                    "verify-recovery",
                                    "--checkpoint-directory",
                                    "/var/run/aecontrol-recovery",
                                    "--drill-id",
                                    drill_id,
                                    "--max-checkpoint-age-hours",
                                    str(configuration.checkpoint_max_age_hours),
                                    "--report-s3",
                                    "--report-retention-days",
                                    str(configuration.report_retention_days),
                                    "--json",
                                ],
                                "env": [
                                    _secret_environment(
                                        "DATABASE_URL", f"{cluster_name}-app", "uri"
                                    ),
                                    _secret_environment(
                                        "AECONTROL_ARTIFACT_ED25519_PUBLIC_KEYS",
                                        configuration.verifier_secret,
                                        "ed25519-public-keys",
                                    ),
                                    *secret_env,
                                ],
                                "resources": {
                                    "requests": {"cpu": "100m", "memory": "128Mi"},
                                    "limits": {"cpu": "500m", "memory": "512Mi"},
                                },
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]},
                                    "readOnlyRootFilesystem": True,
                                },
                                "volumeMounts": [
                                    {
                                        "name": "checkpoints",
                                        "mountPath": "/var/run/aecontrol-recovery",
                                        "readOnly": True,
                                    }
                                ],
                            }
                        ],
                        "volumes": [
                            {
                                "name": "checkpoints",
                                "secret": {
                                    "secretName": configuration.checkpoint_secret,
                                    "defaultMode": 288,
                                },
                            }
                        ],
                    },
                },
            },
        }


def _condition_true(conditions: object, condition_type: str) -> bool:
    if not isinstance(conditions, list):
        return False
    return any(
        isinstance(condition, dict)
        and condition.get("type") == condition_type
        and condition.get("status") == "True"
        for condition in conditions
    )


def _secret_environment(
    name: str, secret_name: str, key: str, *, optional: bool = False
) -> dict[str, Any]:
    selector: dict[str, Any] = {"name": secret_name, "key": key}
    if optional:
        selector["optional"] = True
    return {"name": name, "valueFrom": {"secretKeyRef": selector}}


def _read_namespace() -> str:
    path = Path(
        os.getenv(
            "AECONTROL_KUBERNETES_NAMESPACE_FILE",
            "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
        )
    )
    try:
        with path.open("rb") as stream:
            raw_namespace = stream.read(65)
    except OSError as error:
        raise ValueError("Kubernetes namespace is unavailable") from error
    if len(raw_namespace) > 64:
        raise ValueError("Kubernetes namespace is oversized")
    try:
        namespace = raw_namespace.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ValueError("Kubernetes namespace is not UTF-8") from error
    if len(namespace) > 63:
        raise ValueError("Kubernetes namespace is oversized")
    return namespace


def _bounded_environment_integer(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
