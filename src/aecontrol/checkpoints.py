from __future__ import annotations

import base64
import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aecontrol.integrity import ArtifactKeyring, artifact_digest, canonical_json_bytes
from aecontrol.tenancy import TENANT_ID_PATTERN


class LedgerCheckpointPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    checkpoint_id: UUID
    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    ledger_sequence: int = Field(ge=0)
    ledger_entries: int = Field(ge=0)
    ledger_head_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime
    retention_until: datetime

    @model_validator(mode="after")
    def validate_retention(self) -> LedgerCheckpointPayload:
        if self.created_at.tzinfo is None or self.retention_until.tzinfo is None:
            raise ValueError("checkpoint timestamps must include a timezone")
        if self.retention_until <= self.created_at:
            raise ValueError("checkpoint retention must be after creation")
        return self


class SignedLedgerCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    payload: LedgerCheckpointPayload
    payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    signature_algorithm: Literal["ed25519"] = "ed25519"
    signing_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    signature: str = Field(min_length=1)

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))


class CheckpointPublication(BaseModel):
    checkpoint: SignedLedgerCheckpoint
    destination: str
    object_key: str
    published_at: datetime


class CheckpointPublicationError(RuntimeError):
    pass


class CheckpointSink(Protocol):
    def publish(self, checkpoint: SignedLedgerCheckpoint) -> CheckpointPublication: ...


def checkpoint_payload_digest(payload: LedgerCheckpointPayload) -> str:
    return artifact_digest(payload.model_dump(mode="json"))


def verify_checkpoint(checkpoint: SignedLedgerCheckpoint, keyring: ArtifactKeyring) -> bool:
    digest = checkpoint_payload_digest(checkpoint.payload)
    if digest != checkpoint.payload_sha256:
        return False
    try:
        return keyring.verify(
            checkpoint.signature_algorithm,
            checkpoint.signing_key_id,
            "ledger_checkpoint",
            checkpoint.payload.checkpoint_id,
            digest,
            checkpoint.signature,
        )
    except (KeyError, ValueError):
        return False


def checkpoint_object_key(checkpoint: SignedLedgerCheckpoint) -> str:
    payload = checkpoint.payload
    return (
        f"{payload.tenant_id}/{payload.ledger_sequence:020d}-"
        f"{payload.ledger_head_sha256}-{payload.checkpoint_id}.json"
    )


class FileCheckpointSink:
    """Create-only local sink for demonstrations; host administrators remain trusted."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def publish(self, checkpoint: SignedLedgerCheckpoint) -> CheckpointPublication:
        object_key = checkpoint_object_key(checkpoint)
        destination = (self.root / object_key).resolve()
        if not destination.is_relative_to(self.root):
            raise CheckpointPublicationError("checkpoint path escapes the configured root")
        destination.parent.mkdir(parents=True, exist_ok=True)
        body = checkpoint.canonical_bytes()
        try:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o444,
            )
        except FileExistsError:
            if destination.read_bytes() != body:
                raise CheckpointPublicationError(
                    f"checkpoint destination already contains different bytes: {destination}"
                ) from None
        else:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
        return CheckpointPublication(
            checkpoint=checkpoint,
            destination=str(destination),
            object_key=object_key,
            published_at=datetime.now(UTC),
        )


class S3Client(Protocol):
    def get_object_lock_configuration(self, **kwargs: Any) -> dict[str, Any]: ...

    def put_object(self, **kwargs: Any) -> dict[str, Any]: ...

    def head_object(self, **kwargs: Any) -> dict[str, Any]: ...


class S3ObjectLockCheckpointSink:
    def __init__(
        self, client: S3Client, bucket: str, prefix: str = "aecontrol/checkpoints"
    ) -> None:
        normalized = PurePosixPath(prefix.strip("/"))
        if not bucket or any(part in {"", ".", ".."} for part in normalized.parts):
            raise ValueError("S3 checkpoint bucket and prefix must be normalized")
        self.client = client
        self.bucket = bucket
        self.prefix = str(normalized)

    @classmethod
    def from_environment(cls) -> S3ObjectLockCheckpointSink | None:
        bucket = os.getenv("AECONTROL_CHECKPOINT_S3_BUCKET")
        if not bucket:
            return None
        try:
            import boto3  # type: ignore[import-untyped]
            from botocore.config import Config  # type: ignore[import-untyped]
        except ImportError as error:
            raise RuntimeError("boto3 runtime dependency is unavailable") from error
        client = boto3.client(
            "s3",
            region_name=os.getenv("AECONTROL_CHECKPOINT_S3_REGION"),
            endpoint_url=os.getenv("AECONTROL_CHECKPOINT_S3_ENDPOINT"),
            config=Config(
                connect_timeout=2,
                read_timeout=10,
                retries={"max_attempts": 3, "mode": "standard"},
            ),
        )
        return cls(
            client,
            bucket,
            os.getenv("AECONTROL_CHECKPOINT_S3_PREFIX", "aecontrol/checkpoints"),
        )

    def publish(self, checkpoint: SignedLedgerCheckpoint) -> CheckpointPublication:
        if checkpoint.payload.retention_until <= datetime.now(UTC):
            raise CheckpointPublicationError("checkpoint retention must be in the future")
        try:
            configuration = self.client.get_object_lock_configuration(Bucket=self.bucket)
        except Exception as error:
            response = getattr(error, "response", {})
            code = str(response.get("Error", {}).get("Code", "unknown"))
            raise CheckpointPublicationError(
                f"could not verify S3 Object Lock configuration: {code}"
            ) from error
        if configuration.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") != "Enabled":
            raise CheckpointPublicationError("S3 bucket does not have Object Lock enabled")
        relative_key = checkpoint_object_key(checkpoint)
        key = f"{self.prefix}/{relative_key}"
        body = checkpoint.canonical_bytes()
        body_sha256 = hashlib.sha256(body).hexdigest()
        try:
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=body,
                ContentType="application/json",
                ChecksumSHA256=base64.b64encode(hashlib.sha256(body).digest()).decode(),
                Metadata={"checkpoint-sha256": body_sha256},
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=checkpoint.payload.retention_until,
                IfNoneMatch="*",
            )
        except Exception as error:
            response = getattr(error, "response", {})
            code = str(response.get("Error", {}).get("Code", ""))
            if code not in {"PreconditionFailed", "412"}:
                raise CheckpointPublicationError(
                    f"S3 checkpoint publication failed: {code}"
                ) from error
            existing = self.client.head_object(Bucket=self.bucket, Key=key)
            metadata = existing.get("Metadata", {})
            if metadata.get("checkpoint-sha256") != body_sha256:
                raise CheckpointPublicationError(
                    f"S3 checkpoint key already contains different bytes: s3://{self.bucket}/{key}"
                ) from error
        return CheckpointPublication(
            checkpoint=checkpoint,
            destination=f"s3://{self.bucket}/{key}",
            object_key=key,
            published_at=datetime.now(UTC),
        )
