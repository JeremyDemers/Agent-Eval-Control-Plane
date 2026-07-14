from __future__ import annotations

import hmac
import os
import re
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast
from uuid import UUID

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aecontrol.checkpoints import (
    LedgerCheckpointPayload,
    SignedLedgerCheckpoint,
    verify_checkpoint,
)
from aecontrol.integrity import (
    LEDGER_GENESIS_SHA256,
    ArtifactKeyring,
    artifact_digest,
    ledger_entry_digest,
)
from aecontrol.store import SCHEMA_VERSION

MAX_CHECKPOINT_BYTES = 1024 * 1024
DEFAULT_MAX_CHECKPOINT_AGE_HOURS = 48
DEFAULT_MAX_LEDGER_ENTRIES = 100_000

RecoveryFailureCode = Literal[
    "schema_metadata",
    "schema_version",
    "recovery_in_progress",
    "checkpoint_future",
    "checkpoint_stale",
    "checkpoint_signature",
    "checkpoint_missing",
    "checkpoint_mismatch",
    "ledger_limit",
    "ledger_count",
    "ledger_sequence",
    "ledger_previous_hash",
    "ledger_entry_hash",
    "ledger_head",
    "artifact_missing",
    "artifact_digest",
    "artifact_envelope",
    "artifact_signature",
    "database_schema",
]


class RecoveryVerificationFailure(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: RecoveryFailureCode
    tenant_id: str | None = None
    checkpoint_id: UUID | None = None
    ledger_sequence: int | None = Field(default=None, ge=0)
    artifact_type: str | None = None
    artifact_id: UUID | None = None


class RecoveryCheckpointResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    checkpoint_id: UUID
    tenant_id: str
    ledger_sequence: int = Field(ge=0)
    checkpoint_created_at: datetime
    checkpoint_age_seconds: float = Field(ge=0)
    entries_checked: int = Field(ge=0)
    signed_artifacts: int = Field(ge=0)
    unsigned_artifacts: int = Field(ge=0)
    valid: bool
    failures: list[RecoveryVerificationFailure]


class RecoveryDrillReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    started_at: datetime
    completed_at: datetime
    database: str
    schema_name: str
    expected_schema_version: int = Field(ge=1)
    observed_schema_version: int | None = Field(default=None, ge=0)
    transaction_read_only: bool
    recovery_in_progress: bool
    checkpoints_checked: int = Field(ge=0)
    checkpoints_valid: int = Field(ge=0)
    entries_checked: int = Field(ge=0)
    success: bool
    checkpoint_results: list[RecoveryCheckpointResult]
    failures: list[RecoveryVerificationFailure]


class RecoveryVerificationError(RuntimeError):
    """The recovery database could not be safely inspected."""


def load_recovery_checkpoint(path: Path) -> SignedLedgerCheckpoint:
    """Load a bounded regular checkpoint file without following symlinks."""
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"checkpoint file is unavailable: {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"checkpoint must be a regular non-symlink file: {path}")
    if metadata.st_size > MAX_CHECKPOINT_BYTES:
        raise ValueError(f"checkpoint exceeds {MAX_CHECKPOINT_BYTES} bytes: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            content = stream.read(MAX_CHECKPOINT_BYTES + 1)
    except OSError as error:
        raise ValueError(f"checkpoint file is unavailable: {path}") from error
    if len(content) > MAX_CHECKPOINT_BYTES:
        raise ValueError(f"checkpoint exceeds {MAX_CHECKPOINT_BYTES} bytes: {path}")
    try:
        return SignedLedgerCheckpoint.model_validate_json(content)
    except ValidationError as error:
        raise ValueError(f"checkpoint is not a valid signed envelope: {path}") from error


class RecoveryVerifier:
    """Read-only verification of a restored PostgreSQL database against signed heads."""

    def __init__(
        self,
        database_url: str,
        *,
        schema: str = "public",
        keyring: ArtifactKeyring | None = None,
        max_checkpoint_age_hours: int = DEFAULT_MAX_CHECKPOINT_AGE_HOURS,
        max_ledger_entries: int = DEFAULT_MAX_LEDGER_ENTRIES,
    ) -> None:
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", schema):
            raise ValueError(f"invalid PostgreSQL schema name: {schema}")
        if not 1 <= max_checkpoint_age_hours <= 24 * 30:
            raise ValueError("maximum checkpoint age must be between 1 and 720 hours")
        if not 1 <= max_ledger_entries <= 1_000_000:
            raise ValueError("maximum ledger entries must be between 1 and 1000000")
        self.database_url = database_url
        self.schema = schema
        self.keyring = keyring
        self.max_checkpoint_age = timedelta(hours=max_checkpoint_age_hours)
        self.max_ledger_entries = max_ledger_entries

    def verify(self, checkpoints: list[SignedLedgerCheckpoint]) -> RecoveryDrillReport:
        if not checkpoints:
            raise ValueError("at least one recovery checkpoint is required")
        started_at = datetime.now(UTC)
        database = "unknown"
        observed_version: int | None = None
        read_only = False
        recovery_in_progress = False
        results: list[RecoveryCheckpointResult] = []
        failures: list[RecoveryVerificationFailure] = []
        completed_at = started_at
        try:
            with psycopg.connect(self.database_url, row_factory=dict_row) as connection:
                connection.execute("SET TRANSACTION READ ONLY")
                connection.execute(
                    sql.SQL("SET LOCAL search_path TO {}").format(sql.Identifier(self.schema))
                )
                status = connection.execute(
                    """SELECT current_database() AS database,
                              current_setting('transaction_read_only') AS read_only,
                              pg_is_in_recovery() AS recovery_in_progress,
                              clock_timestamp() AS observed_at,
                              to_regclass('schema_metadata') AS metadata_table"""
                ).fetchone()
                assert status is not None
                database = str(status["database"])
                read_only = status["read_only"] == "on"
                recovery_in_progress = bool(status["recovery_in_progress"])
                observed_at = cast(datetime, status["observed_at"])
                completed_at = observed_at
                if status["metadata_table"] is None:
                    failures.append(RecoveryVerificationFailure(code="schema_metadata"))
                else:
                    metadata = connection.execute(
                        "SELECT version FROM schema_metadata LIMIT 1"
                    ).fetchone()
                    if metadata is None:
                        failures.append(RecoveryVerificationFailure(code="schema_metadata"))
                    else:
                        observed_version = int(str(metadata["version"]))
                        if observed_version != SCHEMA_VERSION:
                            failures.append(RecoveryVerificationFailure(code="schema_version"))
                if recovery_in_progress:
                    failures.append(RecoveryVerificationFailure(code="recovery_in_progress"))
                if not failures:
                    for checkpoint in checkpoints:
                        result = self._verify_checkpoint(connection, checkpoint, observed_at)
                        results.append(result)
                connection.rollback()
        except psycopg.Error as error:
            raise RecoveryVerificationError("recovery database verification failed") from error

        completed_at = max(completed_at, datetime.now(UTC))
        checkpoint_failures = [failure for result in results for failure in result.failures]
        all_failures = [*failures, *checkpoint_failures]
        return RecoveryDrillReport(
            started_at=started_at,
            completed_at=completed_at,
            database=database,
            schema_name=self.schema,
            expected_schema_version=SCHEMA_VERSION,
            observed_schema_version=observed_version,
            transaction_read_only=read_only,
            recovery_in_progress=recovery_in_progress,
            checkpoints_checked=len(results),
            checkpoints_valid=sum(result.valid for result in results),
            entries_checked=sum(result.entries_checked for result in results),
            success=read_only and not all_failures and len(results) == len(checkpoints),
            checkpoint_results=results,
            failures=all_failures,
        )

    def _verify_checkpoint(
        self,
        connection: psycopg.Connection[dict[str, object]],
        checkpoint: SignedLedgerCheckpoint,
        observed_at: datetime,
    ) -> RecoveryCheckpointResult:
        payload = checkpoint.payload
        age = observed_at - payload.created_at
        age_seconds = max(0.0, age.total_seconds())
        failures: list[RecoveryVerificationFailure] = []

        def fail(
            code: RecoveryFailureCode,
            *,
            sequence: int | None = None,
            artifact_type: str | None = None,
            artifact_id: UUID | None = None,
        ) -> None:
            failures.append(
                RecoveryVerificationFailure(
                    code=code,
                    tenant_id=payload.tenant_id,
                    checkpoint_id=payload.checkpoint_id,
                    ledger_sequence=sequence,
                    artifact_type=artifact_type,
                    artifact_id=artifact_id,
                )
            )

        if age < timedelta(minutes=-5):
            fail("checkpoint_future")
        elif age > self.max_checkpoint_age:
            fail("checkpoint_stale")
        if self.keyring is None or not verify_checkpoint(checkpoint, self.keyring):
            fail("checkpoint_signature")
        if payload.ledger_sequence > self.max_ledger_entries:
            fail("ledger_limit")
        if failures:
            return self._checkpoint_result(checkpoint, age_seconds, 0, 0, 0, failures)

        connection.execute(
            "SELECT set_config('aecontrol.tenant_id', %s, true)", (payload.tenant_id,)
        )
        try:
            persisted = connection.execute(
                """SELECT payload, payload_sha256, signature_algorithm,
                          signing_key_id, signature_value
                   FROM ledger_checkpoints WHERE checkpoint_id = %s""",
                (payload.checkpoint_id,),
            ).fetchone()
            if persisted is None:
                fail("checkpoint_missing")
            else:
                try:
                    restored_checkpoint = SignedLedgerCheckpoint(
                        payload=LedgerCheckpointPayload.model_validate(persisted["payload"]),
                        payload_sha256=str(persisted["payload_sha256"]),
                        signature_algorithm=cast(
                            Literal["ed25519"], persisted["signature_algorithm"]
                        ),
                        signing_key_id=str(persisted["signing_key_id"]),
                        signature=str(persisted["signature_value"]),
                    )
                except ValidationError:
                    fail("checkpoint_mismatch")
                else:
                    if restored_checkpoint != checkpoint:
                        fail("checkpoint_mismatch")

            rows = connection.execute(
                """SELECT ledger.sequence, ledger.artifact_type, ledger.artifact_id,
                          ledger.payload_sha256, ledger.signature_algorithm,
                          ledger.signing_key_id, ledger.signature_value,
                          ledger.previous_entry_sha256, ledger.entry_sha256,
                          runs.payload AS run_payload,
                          runs.payload_sha256 AS run_payload_sha256,
                          runs.signature_algorithm AS run_signature_algorithm,
                          runs.signature_key_id AS run_signing_key_id,
                          runs.signature_value AS run_signature_value,
                          comparisons.payload AS comparison_payload,
                          comparisons.payload_sha256 AS comparison_payload_sha256,
                          comparisons.signature_algorithm AS comparison_signature_algorithm,
                          comparisons.signature_key_id AS comparison_signing_key_id,
                          comparisons.signature_value AS comparison_signature_value,
                          evidence.payload AS evidence_payload,
                          evidence.payload_sha256 AS evidence_payload_sha256,
                          evidence.signature_algorithm AS evidence_signature_algorithm,
                          evidence.signature_key_id AS evidence_signing_key_id,
                          evidence.signature_value AS evidence_signature_value
                   FROM artifact_ledger AS ledger
                   LEFT JOIN evaluation_runs AS runs
                     ON ledger.artifact_type = 'run' AND runs.run_id = ledger.artifact_id
                   LEFT JOIN comparisons
                     ON ledger.artifact_type = 'comparison'
                    AND comparisons.comparison_id = ledger.artifact_id
                   LEFT JOIN guardrail_evidence AS evidence
                     ON ledger.artifact_type = 'guardrail_evidence'
                    AND evidence.evidence_id = ledger.artifact_id
                   WHERE ledger.sequence <= %s
                   ORDER BY ledger.sequence""",
                (payload.ledger_sequence,),
            ).fetchall()
        except psycopg.Error:
            fail("database_schema")
            return self._checkpoint_result(checkpoint, age_seconds, 0, 0, 0, failures)

        if len(rows) != payload.ledger_entries or len(rows) != payload.ledger_sequence:
            fail("ledger_count")
        previous = LEDGER_GENESIS_SHA256
        signed = 0
        unsigned = 0
        for expected_sequence, row in enumerate(rows, start=1):
            sequence = int(str(row["sequence"]))
            artifact_type = str(row["artifact_type"])
            artifact_id = cast(UUID, row["artifact_id"])
            ledger_digest = str(row["payload_sha256"])
            algorithm = _optional_string(row["signature_algorithm"])
            key_id = _optional_string(row["signing_key_id"])
            signature = _optional_string(row["signature_value"])
            stored_previous = str(row["previous_entry_sha256"])
            stored_entry = str(row["entry_sha256"])
            if sequence != expected_sequence:
                fail(
                    "ledger_sequence",
                    sequence=sequence,
                    artifact_type=artifact_type,
                    artifact_id=artifact_id,
                )
            if not hmac.compare_digest(stored_previous, previous):
                fail(
                    "ledger_previous_hash",
                    sequence=sequence,
                    artifact_type=artifact_type,
                    artifact_id=artifact_id,
                )
            expected_entry = ledger_entry_digest(
                payload.tenant_id,
                sequence,
                artifact_type,
                artifact_id,
                ledger_digest,
                algorithm,
                key_id,
                signature,
                stored_previous,
            )
            if not hmac.compare_digest(stored_entry, expected_entry):
                fail(
                    "ledger_entry_hash",
                    sequence=sequence,
                    artifact_type=artifact_type,
                    artifact_id=artifact_id,
                )

            source = _source_envelope(row, artifact_type)
            if source is None:
                fail(
                    "artifact_missing",
                    sequence=sequence,
                    artifact_type=artifact_type,
                    artifact_id=artifact_id,
                )
            else:
                source_payload, source_digest, source_algorithm, source_key_id, source_signature = (
                    source
                )
                actual_digest = artifact_digest(source_payload)
                if not hmac.compare_digest(actual_digest, source_digest) or not hmac.compare_digest(
                    source_digest, ledger_digest
                ):
                    fail(
                        "artifact_digest",
                        sequence=sequence,
                        artifact_type=artifact_type,
                        artifact_id=artifact_id,
                    )
                if (source_algorithm, source_key_id, source_signature) != (
                    algorithm,
                    key_id,
                    signature,
                ):
                    fail(
                        "artifact_envelope",
                        sequence=sequence,
                        artifact_type=artifact_type,
                        artifact_id=artifact_id,
                    )
                if algorithm is None and key_id is None and signature is None:
                    unsigned += 1
                elif algorithm is None or key_id is None or signature is None:
                    fail(
                        "artifact_envelope",
                        sequence=sequence,
                        artifact_type=artifact_type,
                        artifact_id=artifact_id,
                    )
                else:
                    signed += 1
                    try:
                        valid_signature = self.keyring is not None and self.keyring.verify(
                            algorithm,
                            key_id,
                            artifact_type,
                            artifact_id,
                            ledger_digest,
                            signature,
                        )
                    except (KeyError, ValueError):
                        valid_signature = False
                    if not valid_signature:
                        fail(
                            "artifact_signature",
                            sequence=sequence,
                            artifact_type=artifact_type,
                            artifact_id=artifact_id,
                        )
            previous = stored_entry

        if not hmac.compare_digest(previous, payload.ledger_head_sha256):
            fail("ledger_head")
        return self._checkpoint_result(
            checkpoint, age_seconds, len(rows), signed, unsigned, failures
        )

    @staticmethod
    def _checkpoint_result(
        checkpoint: SignedLedgerCheckpoint,
        age_seconds: float,
        entries_checked: int,
        signed_artifacts: int,
        unsigned_artifacts: int,
        failures: list[RecoveryVerificationFailure],
    ) -> RecoveryCheckpointResult:
        return RecoveryCheckpointResult(
            checkpoint_id=checkpoint.payload.checkpoint_id,
            tenant_id=checkpoint.payload.tenant_id,
            ledger_sequence=checkpoint.payload.ledger_sequence,
            checkpoint_created_at=checkpoint.payload.created_at,
            checkpoint_age_seconds=age_seconds,
            entries_checked=entries_checked,
            signed_artifacts=signed_artifacts,
            unsigned_artifacts=unsigned_artifacts,
            valid=not failures,
            failures=failures,
        )


def _optional_string(value: object) -> str | None:
    return str(value) if value is not None else None


def _source_envelope(
    row: dict[str, object], artifact_type: str
) -> tuple[object, str, str | None, str | None, str | None] | None:
    prefix = {
        "run": "run",
        "comparison": "comparison",
        "guardrail_evidence": "evidence",
    }.get(artifact_type)
    if prefix is None or row[f"{prefix}_payload"] is None:
        return None
    return (
        row[f"{prefix}_payload"],
        str(row[f"{prefix}_payload_sha256"]),
        _optional_string(row[f"{prefix}_signature_algorithm"]),
        _optional_string(row[f"{prefix}_signing_key_id"]),
        _optional_string(row[f"{prefix}_signature_value"]),
    )
