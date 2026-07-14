from __future__ import annotations

import base64
import hashlib
import os
import re
from datetime import UTC, datetime, timedelta
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


class CheckpointObjectReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    destination_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,31}$")
    destination: str
    object_key: str
    region: str | None = Field(default=None, pattern=r"^[a-z0-9-]{1,32}$")
    body_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    etag: str | None = Field(default=None, max_length=256)
    version_id: str | None = Field(default=None, max_length=1024)
    retention_until: datetime
    verified_at: datetime

    @model_validator(mode="after")
    def validate_timestamps(self) -> CheckpointObjectReceipt:
        if self.retention_until.utcoffset() is None or self.verified_at.utcoffset() is None:
            raise ValueError("checkpoint receipt timestamps must include a timezone")
        return self


class CheckpointPublication(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    checkpoint: SignedLedgerCheckpoint
    destination: str
    object_key: str
    published_at: datetime
    copies: tuple[CheckpointObjectReceipt, ...] = ()
    required_copies: int = Field(default=1, ge=1, le=5)
    failed_destinations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_durability(self) -> CheckpointPublication:
        if len(self.copies) < self.required_copies and (self.copies or self.required_copies > 1):
            raise ValueError("checkpoint publication does not meet its durability policy")
        copy_names = [copy.destination_id for copy in self.copies]
        if len(copy_names) != len(set(copy_names)):
            raise ValueError("checkpoint publication contains duplicate destinations")
        if len(self.failed_destinations) != len(set(self.failed_destinations)) or any(
            not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", name) for name in self.failed_destinations
        ):
            raise ValueError("checkpoint publication contains invalid failed destinations")
        if set(copy_names) & set(self.failed_destinations):
            raise ValueError("checkpoint destination cannot be both successful and failed")
        return self


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

    def get_object(self, **kwargs: Any) -> dict[str, Any]: ...


class S3ObjectLockCheckpointSink:
    def __init__(
        self,
        client: S3Client,
        bucket: str,
        prefix: str = "aecontrol/checkpoints",
        *,
        destination_id: str = "primary",
        region: str | None = None,
    ) -> None:
        normalized = PurePosixPath(prefix.strip("/"))
        if not bucket or any(part in {"", ".", ".."} for part in normalized.parts):
            raise ValueError("S3 checkpoint bucket and prefix must be normalized")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", destination_id):
            raise ValueError("S3 checkpoint destination ID is invalid")
        if region is not None and not re.fullmatch(r"[a-z0-9-]{1,32}", region):
            raise ValueError("S3 checkpoint region is invalid")
        self.client = client
        self.bucket = bucket
        self.prefix = str(normalized)
        self.destination_id = destination_id
        self.region = region

    @classmethod
    def from_environment(cls) -> S3ObjectLockCheckpointSink | None:
        return _s3_sink_from_environment(cls, "AECONTROL_CHECKPOINT_S3", "primary")

    def publish(self, checkpoint: SignedLedgerCheckpoint) -> CheckpointPublication:
        if checkpoint.payload.retention_until <= datetime.now(UTC):
            raise CheckpointPublicationError("checkpoint retention must be in the future")
        try:
            configuration = self.client.get_object_lock_configuration(Bucket=self.bucket)
        except Exception as error:
            code = _aws_error_code(error)
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
                ObjectLockRetainUntilDate=_retention_request_deadline(
                    checkpoint.payload.retention_until
                ),
                IfNoneMatch="*",
            )
        except Exception as error:
            code = _aws_error_code(error)
            if code not in {"PreconditionFailed", "412"}:
                raise CheckpointPublicationError(
                    f"S3 checkpoint publication failed: {code}"
                ) from error
        receipt = self._verify_copy(checkpoint, key, body, body_sha256)
        return CheckpointPublication(
            checkpoint=checkpoint,
            destination=receipt.destination,
            object_key=key,
            published_at=receipt.verified_at,
            copies=(receipt,),
            required_copies=1,
        )

    def _verify_copy(
        self,
        checkpoint: SignedLedgerCheckpoint,
        key: str,
        expected_body: bytes,
        body_sha256: str,
    ) -> CheckpointObjectReceipt:
        try:
            head = self.client.head_object(Bucket=self.bucket, Key=key, ChecksumMode="ENABLED")
            response = self.client.get_object(Bucket=self.bucket, Key=key, ChecksumMode="ENABLED")
            stream = response.get("Body")
            if stream is None or not hasattr(stream, "read"):
                raise CheckpointPublicationError("S3 checkpoint body stream is unavailable")
            close = getattr(stream, "close", None)
            try:
                observed_body = stream.read(1024 * 1024 + 1)
            finally:
                if callable(close):
                    close()
        except CheckpointPublicationError:
            raise
        except Exception as error:
            raise CheckpointPublicationError(
                f"S3 checkpoint read-back verification failed: {_aws_error_code(error)}"
            ) from error
        if not isinstance(observed_body, bytes) or observed_body != expected_body:
            raise CheckpointPublicationError("S3 checkpoint read-back bytes do not match")
        metadata = head.get("Metadata")
        if not isinstance(metadata, dict) or metadata.get("checkpoint-sha256") != body_sha256:
            raise CheckpointPublicationError("S3 checkpoint read-back digest does not match")
        if head.get("ObjectLockMode") != "COMPLIANCE":
            raise CheckpointPublicationError("S3 checkpoint is not under COMPLIANCE retention")
        retained_until = head.get("ObjectLockRetainUntilDate")
        if (
            not isinstance(retained_until, datetime)
            or retained_until.utcoffset() is None
            or retained_until < checkpoint.payload.retention_until
        ):
            raise CheckpointPublicationError("S3 checkpoint retention deadline is insufficient")
        return CheckpointObjectReceipt(
            destination_id=self.destination_id,
            destination=f"s3://{self.bucket}/{key}",
            object_key=key,
            region=self.region,
            body_sha256=body_sha256,
            etag=_optional_response_string(head, "ETag", 256),
            version_id=_optional_response_string(head, "VersionId", 1024),
            retention_until=retained_until,
            verified_at=datetime.now(UTC),
        )


class ReplicatedCheckpointSink:
    def __init__(
        self,
        sinks: tuple[S3ObjectLockCheckpointSink, ...],
        *,
        required_copies: int | None = None,
    ) -> None:
        if not 2 <= len(sinks) <= 5:
            raise ValueError("checkpoint replication requires two to five destinations")
        names = [sink.destination_id for sink in sinks]
        if len(names) != len(set(names)):
            raise ValueError("checkpoint replication destination IDs must be unique")
        resolved_required = len(sinks) if required_copies is None else required_copies
        if not 1 <= resolved_required <= len(sinks):
            raise ValueError("required checkpoint copies must fit the destination count")
        self.sinks = sinks
        self.required_copies = resolved_required

    @classmethod
    def from_environment(cls) -> S3ObjectLockCheckpointSink | ReplicatedCheckpointSink | None:
        primary = S3ObjectLockCheckpointSink.from_environment()
        replica = _s3_sink_from_environment(
            S3ObjectLockCheckpointSink,
            "AECONTROL_CHECKPOINT_REPLICA_S3",
            "replica",
        )
        if primary is None:
            if replica is not None:
                raise ValueError("primary checkpoint S3 bucket is required with a replica")
            return None
        if replica is None:
            return primary
        required = _environment_integer("AECONTROL_CHECKPOINT_REQUIRED_COPIES", 2)
        return cls((primary, replica), required_copies=required)

    def publish(self, checkpoint: SignedLedgerCheckpoint) -> CheckpointPublication:
        copies: list[CheckpointObjectReceipt] = []
        failures: list[str] = []
        for sink in self.sinks:
            try:
                publication = sink.publish(checkpoint)
            except CheckpointPublicationError:
                failures.append(sink.destination_id)
                continue
            copies.extend(publication.copies)
        if len(copies) < self.required_copies:
            succeeded = ",".join(copy.destination_id for copy in copies) or "none"
            failed = ",".join(failures) or "none"
            raise CheckpointPublicationError(
                "checkpoint replication durability policy was not met "
                f"(succeeded={succeeded}; failed={failed})"
            )
        return CheckpointPublication(
            checkpoint=checkpoint,
            destination=f"replicated://{len(copies)}-of-{len(self.sinks)}",
            object_key=checkpoint_object_key(checkpoint),
            published_at=max(copy.verified_at for copy in copies),
            copies=tuple(copies),
            required_copies=self.required_copies,
            failed_destinations=tuple(failures),
        )


def checkpoint_sink_from_environment() -> (
    S3ObjectLockCheckpointSink | ReplicatedCheckpointSink | None
):
    return ReplicatedCheckpointSink.from_environment()


def _s3_sink_from_environment(
    sink_type: type[S3ObjectLockCheckpointSink], variable_prefix: str, destination_id: str
) -> S3ObjectLockCheckpointSink | None:
    bucket = os.getenv(f"{variable_prefix}_BUCKET")
    if not bucket:
        return None
    try:
        import boto3  # type: ignore[import-untyped]
        from botocore.config import Config  # type: ignore[import-untyped]
    except ImportError as error:
        raise RuntimeError("boto3 runtime dependency is unavailable") from error
    region = os.getenv(f"{variable_prefix}_REGION")
    client = boto3.client(
        "s3",
        region_name=region,
        endpoint_url=os.getenv(f"{variable_prefix}_ENDPOINT"),
        config=Config(
            connect_timeout=2,
            read_timeout=10,
            retries={"max_attempts": 3, "mode": "standard"},
        ),
    )
    return sink_type(
        client,
        bucket,
        os.getenv(f"{variable_prefix}_PREFIX", "aecontrol/checkpoints"),
        destination_id=destination_id,
        region=region,
    )


def _aws_error_code(error: Exception) -> str:
    response = getattr(error, "response", {})
    if not isinstance(response, dict):
        return "unknown"
    error_detail = response.get("Error", {})
    if not isinstance(error_detail, dict):
        return "unknown"
    return str(error_detail.get("Code", "unknown"))


def _optional_response_string(response: dict[str, Any], key: str, maximum: int) -> str | None:
    value = response.get(key)
    if value is None:
        return None
    rendered = str(value)
    return rendered if len(rendered) <= maximum else None


def _environment_integer(name: str, default: int) -> int:
    value = os.getenv(name)
    try:
        return default if value is None else int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error


def _retention_request_deadline(value: datetime) -> datetime:
    if value.microsecond == 0:
        return value
    return value.replace(microsecond=0) + timedelta(seconds=1)
