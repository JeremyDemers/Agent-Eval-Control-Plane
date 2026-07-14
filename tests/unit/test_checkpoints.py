from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from aecontrol.checkpoints import (
    CheckpointPublicationError,
    FileCheckpointSink,
    LedgerCheckpointPayload,
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
    def __init__(self, *, lock_enabled: bool = True, duplicate: bool = False) -> None:
        self.lock_enabled = lock_enabled
        self.duplicate = duplicate
        self.put: dict[str, Any] | None = None
        self.metadata: dict[str, str] = {}

    def get_object_lock_configuration(self, **_kwargs: Any) -> dict[str, Any]:
        state = "Enabled" if self.lock_enabled else "Disabled"
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": state}}

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.put = kwargs
        if self.duplicate:
            self.metadata = kwargs["Metadata"]
            raise _PreconditionFailedError
        return {}

    def head_object(self, **_kwargs: Any) -> dict[str, Any]:
        return {"Metadata": self.metadata}


def test_s3_checkpoint_sink_requires_compliance_lock_and_is_idempotent() -> None:
    checkpoint, _verifier = _signed_checkpoint()
    client = FakeS3Client()
    sink = S3ObjectLockCheckpointSink(client, "evidence", "checkpoints/releases")

    publication = sink.publish(checkpoint)

    assert publication.destination.startswith("s3://evidence/checkpoints/releases/research/")
    assert client.put is not None
    assert client.put["ObjectLockMode"] == "COMPLIANCE"
    assert client.put["ObjectLockRetainUntilDate"] == checkpoint.payload.retention_until
    assert client.put["IfNoneMatch"] == "*"
    assert client.put["Body"] == checkpoint.canonical_bytes()

    client.duplicate = True
    assert sink.publish(checkpoint).object_key == publication.object_key

    with pytest.raises(CheckpointPublicationError, match="Object Lock"):
        S3ObjectLockCheckpointSink(FakeS3Client(lock_enabled=False), "evidence").publish(checkpoint)
