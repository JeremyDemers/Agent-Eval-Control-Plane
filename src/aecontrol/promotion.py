from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from aecontrol.recovery_drill import KUBERNETES_DNS_LABEL

MAX_PROMOTION_TOKEN_BYTES = 16 * 1024
MAX_DECODED_TOKEN_BYTES = 8 * 1024
TOKEN_FIELDS = frozenset(
    {
        "latestCheckpointTimelineID",
        "redoWalFile",
        "databaseSystemIdentifier",
        "latestCheckpointREDOLocation",
        "timeOfLatestCheckpoint",
        "operatorVersion",
    }
)
WAL_FILE = re.compile(r"^[0-9A-F]{24}$")
LSN = re.compile(r"^[0-9A-F]+/[0-9A-F]+$")


class PromotionError(RuntimeError):
    """A guarded CloudNativePG promotion could not complete."""


class PromotionToken(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    latest_checkpoint_timeline_id: str = Field(alias="latestCheckpointTimelineID")
    redo_wal_file: str = Field(alias="redoWalFile")
    database_system_identifier: str = Field(alias="databaseSystemIdentifier")
    latest_checkpoint_redo_location: str = Field(alias="latestCheckpointREDOLocation")
    time_of_latest_checkpoint: str = Field(alias="timeOfLatestCheckpoint")
    operator_version: str = Field(alias="operatorVersion")

    def model_post_init(self, _context: Any) -> None:
        if not self.latest_checkpoint_timeline_id.isdigit():
            raise ValueError("promotion token timeline ID is invalid")
        if not WAL_FILE.fullmatch(self.redo_wal_file):
            raise ValueError("promotion token REDO WAL file is invalid")
        if not self.database_system_identifier.isdigit():
            raise ValueError("promotion token database system identifier is invalid")
        if not LSN.fullmatch(self.latest_checkpoint_redo_location):
            raise ValueError("promotion token REDO location is invalid")
        for name, value in (
            ("checkpoint time", self.time_of_latest_checkpoint),
            ("operator version", self.operator_version),
        ):
            if not value or len(value) > 128 or not value.isprintable():
                raise ValueError(f"promotion token {name} is invalid")


class PromotionConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    namespace: str
    target_cluster: str
    source_cluster: str
    token_file: Path
    timeout_seconds: int = Field(default=1800, ge=60, le=7200)
    poll_seconds: int = Field(default=10, ge=2, le=60)
    expected_operator_version: str | None = Field(default=None, max_length=128)

    def model_post_init(self, _context: Any) -> None:
        for name in ("namespace", "target_cluster", "source_cluster"):
            if not KUBERNETES_DNS_LABEL.fullmatch(str(getattr(self, name))):
                raise ValueError(f"{name.replace('_', ' ')} must be a Kubernetes DNS label")
        if self.target_cluster == self.source_cluster:
            raise ValueError("target cluster and source cluster must differ")

    @classmethod
    def from_environment(cls) -> PromotionConfiguration:
        namespace = os.getenv("AECONTROL_PROMOTION_NAMESPACE")
        target = os.getenv("AECONTROL_PROMOTION_TARGET_CLUSTER")
        source = os.getenv("AECONTROL_PROMOTION_SOURCE_CLUSTER")
        token_file = os.getenv("AECONTROL_PROMOTION_TOKEN_FILE")
        required = {
            "AECONTROL_PROMOTION_NAMESPACE": namespace,
            "AECONTROL_PROMOTION_TARGET_CLUSTER": target,
            "AECONTROL_PROMOTION_SOURCE_CLUSTER": source,
            "AECONTROL_PROMOTION_TOKEN_FILE": token_file,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(f"{', '.join(missing)} is required")
        return cls(
            namespace=str(namespace),
            target_cluster=str(target),
            source_cluster=str(source),
            token_file=Path(str(token_file)),
            timeout_seconds=_environment_integer("AECONTROL_PROMOTION_TIMEOUT_SECONDS", 1800),
            poll_seconds=_environment_integer("AECONTROL_PROMOTION_POLL_SECONDS", 10),
            expected_operator_version=os.getenv("AECONTROL_PROMOTION_EXPECTED_OPERATOR_VERSION"),
        )


class PromotionOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target_cluster: str
    source_cluster: str
    database_system_identifier: str
    latest_checkpoint_timeline_id: str
    latest_checkpoint_redo_location: str
    time_of_latest_checkpoint: str
    operator_version: str
    token_sha256: str
    promoted_at: datetime
    duration_seconds: float = Field(ge=0)
    success: bool


class PromotionKubernetesClient(Protocol):
    def get_cluster(self, namespace: str, name: str) -> dict[str, Any]: ...

    def patch_cluster(self, namespace: str, name: str, body: dict[str, Any]) -> dict[str, Any]: ...


def parse_promotion_token(raw_token: str) -> PromotionToken:
    try:
        encoded = raw_token.encode("ascii")
    except UnicodeEncodeError as error:
        raise PromotionError("promotion token is not ASCII") from error
    if not encoded or len(encoded) > MAX_PROMOTION_TOKEN_BYTES or raw_token.strip() != raw_token:
        raise PromotionError("promotion token is empty, padded with whitespace, or oversized")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise PromotionError("promotion token is not valid base64") from error
    if len(decoded) > MAX_DECODED_TOKEN_BYTES:
        raise PromotionError("decoded promotion token is oversized")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise PromotionError("promotion token contains duplicate JSON fields")
            value[key] = item
        return value

    try:
        payload = json.loads(decoded, object_pairs_hook=reject_duplicate_keys)
    except PromotionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PromotionError("promotion token is not valid UTF-8 JSON") from error
    if not isinstance(payload, dict) or set(payload) != TOKEN_FIELDS:
        raise PromotionError("promotion token fields do not match the CloudNativePG contract")
    try:
        return PromotionToken.model_validate(payload)
    except ValueError as error:
        raise PromotionError("promotion token content is invalid") from error


def load_promotion_token(path: Path) -> tuple[str, PromotionToken]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_PROMOTION_TOKEN_BYTES + 1)
    except OSError as error:
        raise PromotionError("promotion token file is unavailable") from error
    if len(raw) > MAX_PROMOTION_TOKEN_BYTES:
        raise PromotionError("promotion token file is oversized")
    try:
        token = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise PromotionError("promotion token file is not ASCII") from error
    return token, parse_promotion_token(token)


class PromotionOrchestrator:
    def __init__(
        self,
        configuration: PromotionConfiguration,
        client: PromotionKubernetesClient,
        *,
        now: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.configuration = configuration
        self.client = client
        self.now = now or (lambda: datetime.now(UTC))
        self.monotonic = monotonic or time.monotonic
        self.sleep = sleep or time.sleep

    def run(self) -> PromotionOutcome:
        started_at = self.now()
        raw_token, token = load_promotion_token(self.configuration.token_file)
        self._validate_operator_version(token)
        cluster = self.client.get_cluster(
            self.configuration.namespace, self.configuration.target_cluster
        )
        resource_version = self._preflight(cluster, token)
        self.client.patch_cluster(
            self.configuration.namespace,
            self.configuration.target_cluster,
            {
                "apiVersion": "postgresql.cnpg.io/v1",
                "kind": "Cluster",
                "metadata": {"resourceVersion": resource_version},
                "spec": {
                    "replica": {
                        "primary": self.configuration.target_cluster,
                        "source": self.configuration.source_cluster,
                        "promotionToken": raw_token,
                    }
                },
            },
        )
        self._wait_for_promotion(raw_token)
        promoted_at = self.now()
        return PromotionOutcome(
            target_cluster=self.configuration.target_cluster,
            source_cluster=self.configuration.source_cluster,
            database_system_identifier=token.database_system_identifier,
            latest_checkpoint_timeline_id=token.latest_checkpoint_timeline_id,
            latest_checkpoint_redo_location=token.latest_checkpoint_redo_location,
            time_of_latest_checkpoint=token.time_of_latest_checkpoint,
            operator_version=token.operator_version,
            token_sha256=hashlib.sha256(raw_token.encode("ascii")).hexdigest(),
            promoted_at=promoted_at,
            duration_seconds=max(0.0, (promoted_at - started_at).total_seconds()),
            success=True,
        )

    def _validate_operator_version(self, token: PromotionToken) -> None:
        expected = self.configuration.expected_operator_version
        if expected is not None and token.operator_version != expected:
            raise PromotionError("promotion token operator version does not match policy")

    def _preflight(self, cluster: dict[str, Any], token: PromotionToken) -> str:
        metadata = _mapping(cluster.get("metadata"), "cluster metadata")
        spec = _mapping(cluster.get("spec"), "cluster spec")
        replica = _mapping(spec.get("replica"), "cluster replica configuration")
        status = _mapping(cluster.get("status"), "cluster status")
        resource_version = metadata.get("resourceVersion")
        if not isinstance(resource_version, str) or not resource_version:
            raise PromotionError("target cluster resourceVersion is unavailable")
        expected_source = self.configuration.source_cluster
        if replica.get("primary") != expected_source or replica.get("source") != expected_source:
            raise PromotionError("target cluster is not following the expected source")
        if replica.get("promotionToken"):
            raise PromotionError("target cluster already has a promotion token")
        if replica.get("minApplyDelay"):
            raise PromotionError("delayed replicas cannot use controlled promotion")
        if str(status.get("systemID", "")) != token.database_system_identifier:
            raise PromotionError("promotion token system identifier does not match the target")
        switch = status.get("switchReplicaClusterStatus", {})
        if isinstance(switch, dict) and switch.get("inProgress") is True:
            raise PromotionError("target cluster is already changing replica state")
        if not _condition_true(status.get("conditions"), "Ready"):
            raise PromotionError("target cluster is not Ready")
        return resource_version

    def _wait_for_promotion(self, raw_token: str) -> None:
        deadline = self.monotonic() + self.configuration.timeout_seconds
        while self.monotonic() < deadline:
            cluster = self.client.get_cluster(
                self.configuration.namespace, self.configuration.target_cluster
            )
            spec = cluster.get("spec", {})
            status = cluster.get("status", {})
            replica = spec.get("replica", {}) if isinstance(spec, dict) else {}
            if (
                isinstance(replica, dict)
                and isinstance(status, dict)
                and replica.get("primary") == self.configuration.target_cluster
                and status.get("lastPromotionToken") == raw_token
                and _condition_true(status.get("conditions"), "Ready")
            ):
                return
            phase = str(status.get("phase", "")) if isinstance(status, dict) else ""
            if phase.lower() in {"error", "unrecoverable"}:
                raise PromotionError("target cluster entered a terminal failure phase")
            self.sleep(self.configuration.poll_seconds)
        raise PromotionError("target cluster promotion timed out")


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PromotionError(f"{name} is unavailable")
    return value


def _condition_true(value: Any, condition_type: str) -> bool:
    if not isinstance(value, list):
        return False
    return any(
        isinstance(item, dict)
        and item.get("type") == condition_type
        and item.get("status") == "True"
        for item in value
    )


def _environment_integer(name: str, default: int) -> int:
    value = os.getenv(name)
    try:
        return default if value is None else int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
