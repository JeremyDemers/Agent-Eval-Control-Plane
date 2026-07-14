from __future__ import annotations

import hashlib
import io
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from aecontrol.checkpoints import (
    CheckpointPublication,
    CheckpointPublicationError,
    FileCheckpointSink,
    LedgerCheckpointPayload,
    ReplicatedCheckpointSink,
    S3ObjectLockCheckpointSink,
    SignedLedgerCheckpoint,
    checkpoint_payload_digest,
    verify_checkpoint,
)
from aecontrol.integrity import ED25519, ArtifactKeyring, generate_ed25519_keypair


def _signed_checkpoint() -> tuple[SignedLedgerCheckpoint, ArtifactKeyring]:
    private_key, public_key = generate_ed25519_keypair()
    signer = ArtifactKeyring(
        active_key_id="checkpoint-key",
        active_algorithm=ED25519,
        ed25519_private_keys={"checkpoint-key": private_key},
    )
    verifier = ArtifactKeyring(ed25519_public_keys={"checkpoint-key": public_key})
    created_at = datetime.now(UTC)
    payload = LedgerCheckpointPayload(
        checkpoint_id=uuid4(),
        tenant_id="research",
        ledger_sequence=7,
        ledger_entries=7,
        ledger_head_sha256="a" * 64,
        created_at=created_at,
        retention_until=created_at + timedelta(days=30),
    )
    digest = checkpoint_payload_digest(payload)
    checkpoint = SignedLedgerCheckpoint(
        payload=payload,
        payload_sha256=digest,
        signing_key_id="checkpoint-key",
        signature=signer.sign("ledger_checkpoint", payload.checkpoint_id, digest),
    )
    return checkpoint, verifier


def test_checkpoint_public_verification_rejects_payload_drift() -> None:
    checkpoint, verifier = _signed_checkpoint()

    assert verify_checkpoint(checkpoint, verifier) is True
    changed = checkpoint.model_copy(
        update={"payload": checkpoint.payload.model_copy(update={"ledger_head_sha256": "b" * 64})}
    )
    assert verify_checkpoint(changed, verifier) is False

    with pytest.raises(ValueError, match="retention must be after"):
        LedgerCheckpointPayload(
            checkpoint_id=uuid4(),
            tenant_id="research",
            ledger_sequence=0,
            ledger_entries=0,
            ledger_head_sha256="0" * 64,
            created_at=checkpoint.payload.created_at,
            retention_until=checkpoint.payload.created_at,
        )


def test_file_checkpoint_sink_is_create_only_and_idempotent(tmp_path: Path) -> None:
    checkpoint, _verifier = _signed_checkpoint()
    sink = FileCheckpointSink(tmp_path)

    first = sink.publish(checkpoint)
    second = sink.publish(checkpoint)

    destination = Path(first.destination)
    assert first.object_key == second.object_key
    assert destination.read_bytes() == checkpoint.canonical_bytes()
    assert destination.stat().st_mode & 0o777 == 0o444

    destination.chmod(0o644)
    destination.write_text("different")
    with pytest.raises(CheckpointPublicationError, match="different bytes"):
        sink.publish(checkpoint)


class _PreconditionFailedError(Exception):
    def __init__(self) -> None:
        self.response = {"Error": {"Code": "PreconditionFailed"}}


class FakeS3Client:
    def __init__(
        self,
        *,
        lock_enabled: bool = True,
        duplicate: bool = False,
        fail_put: bool = False,
    ) -> None:
        self.lock_enabled = lock_enabled
        self.duplicate = duplicate
        self.fail_put = fail_put
        self.put: dict[str, Any] | None = None
        self.metadata: dict[str, str] = {}
        self.body = b""
        self.retention_until: datetime | None = None
        self.lock_mode = "COMPLIANCE"

    def get_object_lock_configuration(self, **_kwargs: Any) -> dict[str, Any]:
        state = "Enabled" if self.lock_enabled else "Disabled"
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": state}}

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.put = kwargs
        if self.fail_put:
            raise RuntimeError("sensitive provider detail")
        if self.duplicate:
            raise _PreconditionFailedError
        self.metadata = kwargs["Metadata"]
        self.body = kwargs["Body"]
        self.retention_until = kwargs["ObjectLockRetainUntilDate"]
        return {}

    def head_object(self, **_kwargs: Any) -> dict[str, Any]:
        return {
            "Metadata": self.metadata,
            "ObjectLockMode": self.lock_mode,
            "ObjectLockRetainUntilDate": self.retention_until,
            "ETag": '"checkpoint-etag"',
            "VersionId": "version-7",
        }

    def get_object(self, **_kwargs: Any) -> dict[str, Any]:
        return {"Body": io.BytesIO(self.body)}


def test_s3_checkpoint_sink_requires_compliance_lock_and_is_idempotent() -> None:
    checkpoint, _verifier = _signed_checkpoint()
    client = FakeS3Client()
    sink = S3ObjectLockCheckpointSink(client, "evidence", "checkpoints/releases")

    publication = sink.publish(checkpoint)

    assert publication.destination.startswith("s3://evidence/checkpoints/releases/research/")
    assert client.put is not None
    assert client.put["ObjectLockMode"] == "COMPLIANCE"
    assert client.put["ObjectLockRetainUntilDate"] >= checkpoint.payload.retention_until
    assert client.put["ObjectLockRetainUntilDate"].microsecond == 0
    assert client.put["IfNoneMatch"] == "*"
    assert client.put["Body"] == checkpoint.canonical_bytes()
    assert publication.required_copies == 1
    assert len(publication.copies) == 1
    receipt = publication.copies[0]
    assert receipt.destination_id == "primary"
    assert receipt.body_sha256 == client.put["Metadata"]["checkpoint-sha256"]
    assert receipt.etag == '"checkpoint-etag"'
    assert receipt.version_id == "version-7"
    assert receipt.retention_until >= checkpoint.payload.retention_until

    client.duplicate = True
    assert sink.publish(checkpoint).object_key == publication.object_key

    with pytest.raises(CheckpointPublicationError, match="Object Lock"):
        S3ObjectLockCheckpointSink(FakeS3Client(lock_enabled=False), "evidence").publish(checkpoint)


def test_s3_checkpoint_sink_fails_closed_on_readback_or_retention_drift() -> None:
    checkpoint, _verifier = _signed_checkpoint()
    changed = FakeS3Client()
    changed.body = b"different"
    changed.duplicate = True
    changed.metadata = {"checkpoint-sha256": "0" * 64}
    changed.retention_until = checkpoint.payload.retention_until
    with pytest.raises(CheckpointPublicationError, match="bytes do not match"):
        S3ObjectLockCheckpointSink(changed, "evidence").publish(checkpoint)

    unlocked = FakeS3Client()
    unlocked.lock_mode = "GOVERNANCE"
    with pytest.raises(CheckpointPublicationError, match="COMPLIANCE"):
        S3ObjectLockCheckpointSink(unlocked, "evidence").publish(checkpoint)

    short = FakeS3Client()
    short.retention_until = checkpoint.payload.created_at
    short.duplicate = True
    short.body = checkpoint.canonical_bytes()
    short.metadata = {"checkpoint-sha256": hashlib.sha256(short.body).hexdigest()}
    with pytest.raises(CheckpointPublicationError, match="deadline"):
        S3ObjectLockCheckpointSink(short, "evidence").publish(checkpoint)


def test_replicated_checkpoint_sink_requires_policy_and_reports_verified_copies() -> None:
    checkpoint, _verifier = _signed_checkpoint()
    primary = FakeS3Client()
    replica = FakeS3Client()
    sink = ReplicatedCheckpointSink(
        (
            S3ObjectLockCheckpointSink(
                primary, "evidence-primary", destination_id="primary", region="us-east-1"
            ),
            S3ObjectLockCheckpointSink(
                replica, "evidence-replica", destination_id="replica", region="us-west-2"
            ),
        )
    )

    publication = sink.publish(checkpoint)

    assert publication.destination == "replicated://2-of-2"
    assert publication.required_copies == 2
    assert publication.failed_destinations == ()
    assert {copy.destination_id for copy in publication.copies} == {"primary", "replica"}
    assert {copy.region for copy in publication.copies} == {"us-east-1", "us-west-2"}
    assert {copy.body_sha256 for copy in publication.copies} == {
        hashlib.sha256(checkpoint.canonical_bytes()).hexdigest()
    }


def test_replicated_checkpoint_sink_retries_partial_success_and_supports_explicit_quorum() -> None:
    checkpoint, _verifier = _signed_checkpoint()
    primary = FakeS3Client()
    replica = FakeS3Client(fail_put=True)
    primary_sink = S3ObjectLockCheckpointSink(primary, "primary", destination_id="primary")
    replica_sink = S3ObjectLockCheckpointSink(replica, "replica", destination_id="replica")

    strict = ReplicatedCheckpointSink((primary_sink, replica_sink))
    with pytest.raises(CheckpointPublicationError, match="succeeded=primary; failed=replica"):
        strict.publish(checkpoint)

    primary.duplicate = True
    replica.fail_put = False
    retried = strict.publish(checkpoint)
    assert len(retried.copies) == 2

    replica.fail_put = True
    primary.duplicate = True
    quorum = ReplicatedCheckpointSink((primary_sink, replica_sink), required_copies=1)
    degraded = quorum.publish(checkpoint)
    assert degraded.destination == "replicated://1-of-2"
    assert degraded.required_copies == 1
    assert degraded.failed_destinations == ("replica",)


def test_replication_environment_policy_and_publication_model_are_strict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = S3ObjectLockCheckpointSink(FakeS3Client(), "primary", destination_id="primary")
    replica = S3ObjectLockCheckpointSink(FakeS3Client(), "replica", destination_id="replica")

    def configured_sink(
        _sink_type: object, _prefix: str, destination_id: str
    ) -> S3ObjectLockCheckpointSink:
        return {"primary": primary, "replica": replica}[destination_id]

    monkeypatch.setattr("aecontrol.checkpoints._s3_sink_from_environment", configured_sink)
    monkeypatch.setenv("AECONTROL_CHECKPOINT_REQUIRED_COPIES", "1")
    configured = ReplicatedCheckpointSink.from_environment()
    assert isinstance(configured, ReplicatedCheckpointSink)
    assert configured.required_copies == 1

    checkpoint, _verifier = _signed_checkpoint()
    with pytest.raises(ValueError, match="durability policy"):
        CheckpointPublication(
            checkpoint=checkpoint,
            destination="replicated://1-of-2",
            object_key="checkpoint.json",
            published_at=datetime.now(UTC),
            copies=primary.publish(checkpoint).copies,
            required_copies=2,
        )
    with pytest.raises(ValueError, match="durability policy"):
        CheckpointPublication(
            checkpoint=checkpoint,
            destination="replicated://0-of-2",
            object_key="checkpoint.json",
            published_at=datetime.now(UTC),
            required_copies=2,
        )
    with pytest.raises(ValueError, match="invalid failed"):
        CheckpointPublication(
            checkpoint=checkpoint,
            destination="replicated://1-of-2",
            object_key="checkpoint.json",
            published_at=datetime.now(UTC),
            copies=primary.publish(checkpoint).copies,
            failed_destinations=("Invalid_Name",),
        )
