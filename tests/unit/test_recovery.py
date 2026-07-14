from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from typer.testing import CliRunner

from aecontrol.checkpoints import LedgerCheckpointPayload, SignedLedgerCheckpoint
from aecontrol.cli import app
from aecontrol.integrity import ArtifactKeyring, artifact_digest, generate_ed25519_keypair
from aecontrol.recovery import (
    MAX_CHECKPOINT_BYTES,
    RecoveryCheckpointResult,
    RecoveryDrillReport,
    RecoveryReportPublicationError,
    RecoveryVerificationFailure,
    RecoveryVerifier,
    S3ObjectLockRecoveryReportSink,
    load_recovery_checkpoint,
    load_recovery_checkpoint_directory,
)


def _checkpoint() -> SignedLedgerCheckpoint:
    private_key, _public_key = generate_ed25519_keypair()
    signer = ArtifactKeyring(
        active_key_id="recovery-key",
        active_algorithm="ed25519",
        ed25519_private_keys={"recovery-key": private_key},
    )
    now = datetime.now(UTC)
    payload = LedgerCheckpointPayload(
        checkpoint_id=uuid4(),
        tenant_id="research",
        ledger_sequence=0,
        ledger_entries=0,
        ledger_head_sha256="0" * 64,
        created_at=now,
        retention_until=now + timedelta(days=30),
    )
    digest = artifact_digest(payload.model_dump(mode="json"))
    return SignedLedgerCheckpoint(
        payload=payload,
        payload_sha256=digest,
        signing_key_id="recovery-key",
        signature=signer.sign("ledger_checkpoint", payload.checkpoint_id, digest),
    )


def test_recovery_checkpoint_loader_accepts_only_bounded_regular_envelopes(tmp_path: Path) -> None:
    checkpoint = _checkpoint()
    valid = tmp_path / "checkpoint.json"
    valid.write_bytes(checkpoint.canonical_bytes())

    assert load_recovery_checkpoint(valid) == checkpoint

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{}")
    with pytest.raises(ValueError, match="valid signed envelope"):
        load_recovery_checkpoint(malformed)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (MAX_CHECKPOINT_BYTES + 1))
    with pytest.raises(ValueError, match="exceeds"):
        load_recovery_checkpoint(oversized)


def test_recovery_checkpoint_loader_rejects_symlinks(tmp_path: Path) -> None:
    destination = tmp_path / "checkpoint.json"
    destination.write_bytes(_checkpoint().canonical_bytes())
    link = tmp_path / "checkpoint-link.json"
    link.symlink_to(destination)

    with pytest.raises(ValueError, match="non-symlink"):
        load_recovery_checkpoint(link)


def test_recovery_checkpoint_directory_is_sorted_and_bounded(tmp_path: Path) -> None:
    first = _checkpoint()
    second = _checkpoint()
    (tmp_path / "b.json").write_bytes(second.canonical_bytes())
    (tmp_path / "a.json").write_bytes(first.canonical_bytes())
    (tmp_path / "ignored.txt").write_text("not a checkpoint")

    assert load_recovery_checkpoint_directory(tmp_path) == [first, second]

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="contains no JSON"):
        load_recovery_checkpoint_directory(empty)

    link = tmp_path / "linked-directory"
    link.symlink_to(empty, target_is_directory=True)
    with pytest.raises(ValueError, match="non-symlink directory"):
        load_recovery_checkpoint_directory(link)


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"schema": "public;drop schema public"}, "invalid PostgreSQL schema"),
        ({"max_checkpoint_age_hours": 0}, "maximum checkpoint age"),
        ({"max_ledger_entries": 1_000_001}, "maximum ledger entries"),
    ],
)
def test_recovery_verifier_configuration_is_bounded(
    options: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        RecoveryVerifier("postgresql://localhost/aecontrol", **options)  # type: ignore[arg-type]


def test_recovery_verifier_requires_external_checkpoint() -> None:
    verifier = RecoveryVerifier("postgresql://localhost/aecontrol")

    with pytest.raises(ValueError, match="at least one"):
        verifier.verify([])

    checkpoints = [_checkpoint() for _ in range(17)]
    with pytest.raises(ValueError, match="at most 16"):
        verifier.verify(checkpoints)

    with pytest.raises(ValueError, match="Kubernetes DNS label"):
        verifier.verify([_checkpoint()], drill_id="Invalid_Drill")


def test_recovery_cli_emits_machine_report_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkpoint = _checkpoint()
    checkpoint_file = tmp_path / "checkpoint.json"
    checkpoint_file.write_bytes(checkpoint.canonical_bytes())
    now = datetime.now(UTC)
    failure = RecoveryVerificationFailure(
        code="checkpoint_stale",
        tenant_id=checkpoint.payload.tenant_id,
        checkpoint_id=checkpoint.payload.checkpoint_id,
    )
    checkpoint_result = RecoveryCheckpointResult(
        checkpoint_id=checkpoint.payload.checkpoint_id,
        tenant_id=checkpoint.payload.tenant_id,
        ledger_sequence=0,
        checkpoint_created_at=checkpoint.payload.created_at,
        checkpoint_age_seconds=172_800,
        entries_checked=0,
        signed_artifacts=0,
        unsigned_artifacts=0,
        valid=False,
        failure_count=1,
        failures_truncated=False,
        failures=[failure],
    )
    report = RecoveryDrillReport(
        drill_id="drill-20260714t120000z",
        started_at=now,
        completed_at=now,
        database="aecontrol_restore",
        schema_name="public",
        expected_schema_version=18,
        observed_schema_version=18,
        transaction_read_only=True,
        recovery_in_progress=False,
        checkpoints_checked=1,
        checkpoints_valid=0,
        entries_checked=0,
        success=False,
        failure_count=1,
        failures_truncated=False,
        checkpoint_results=[checkpoint_result],
        failures=[failure],
    )

    class Verifier:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def verify(
            self,
            _checkpoints: list[SignedLedgerCheckpoint],
            *,
            drill_id: str | None = None,
        ) -> RecoveryDrillReport:
            assert drill_id is None
            return report

    monkeypatch.setattr("aecontrol.cli.RecoveryVerifier", Verifier)
    result = CliRunner().invoke(
        app,
        ["store", "verify-recovery", "--checkpoint", str(checkpoint_file), "--json"],
    )

    assert result.exit_code == 1
    payload = report.model_dump_json(indent=2)
    assert '"success": false' in result.output
    assert '"checkpoint_stale"' in result.output
    assert "aecontrol_restore" in result.output
    assert "postgresql://" not in result.output
    assert payload.strip() == result.output.strip()


class _PreconditionFailedError(Exception):
    def __init__(self) -> None:
        self.response = {"Error": {"Code": "PreconditionFailed"}}


class _FakeS3Client:
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
            raise _PreconditionFailedError
        self.metadata = kwargs["Metadata"]
        return {}

    def head_object(self, **_kwargs: Any) -> dict[str, Any]:
        return {"Metadata": self.metadata}


def test_recovery_report_archive_is_create_only_compliance_locked_and_idempotent() -> None:
    now = datetime.now(UTC)
    report = RecoveryDrillReport(
        drill_id="drill-20260714t120000z",
        started_at=now,
        completed_at=now,
        database="aecontrol_restore",
        schema_name="public",
        expected_schema_version=18,
        observed_schema_version=18,
        transaction_read_only=True,
        recovery_in_progress=False,
        checkpoints_checked=1,
        checkpoints_valid=1,
        entries_checked=7,
        success=True,
        failure_count=0,
        failures_truncated=False,
        checkpoint_results=[],
        failures=[],
    )
    client = _FakeS3Client()
    sink = S3ObjectLockRecoveryReportSink(client, "evidence", "drills/recovery")

    publication = sink.publish(report, retention_days=90)

    assert publication.destination.startswith("s3://evidence/drills/recovery/")
    assert publication.object_key.endswith(f"/{report.drill_id}.json")
    assert client.put is not None
    assert client.put["Body"] == report.canonical_bytes()
    assert client.put["IfNoneMatch"] == "*"
    assert client.put["ObjectLockMode"] == "COMPLIANCE"
    assert client.put["Metadata"]["drill-id"] == report.drill_id

    client.duplicate = True
    assert sink.publish(report).object_key == publication.object_key

    with pytest.raises(RecoveryReportPublicationError, match="Object Lock"):
        S3ObjectLockRecoveryReportSink(_FakeS3Client(lock_enabled=False), "evidence").publish(
            report
        )

    with pytest.raises(ValueError, match="normalized"):
        S3ObjectLockRecoveryReportSink(client, "evidence", "../escape")
    with pytest.raises(ValueError, match="normalized"):
        S3ObjectLockRecoveryReportSink(client, "bad\nbucket")


def test_recovery_result_records_truncated_failure_count() -> None:
    checkpoint = _checkpoint()
    failures = [
        RecoveryVerificationFailure(
            code="artifact_missing",
            tenant_id="research",
            checkpoint_id=checkpoint.payload.checkpoint_id,
        )
        for _ in range(20)
    ]

    result = RecoveryVerifier._checkpoint_result(
        checkpoint,
        age_seconds=1,
        entries_checked=25,
        signed_artifacts=0,
        unsigned_artifacts=0,
        failure_count=25,
        failures=failures,
    )

    assert result.valid is False
    assert result.failure_count == 25
    assert result.failures_truncated is True
    assert len(result.failures) == 20
