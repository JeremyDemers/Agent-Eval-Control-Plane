from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol, cast
from uuid import UUID, uuid4

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
    canonical_json_bytes,
    ledger_entry_digest,
)
from aecontrol.store import SCHEMA_VERSION

MAX_CHECKPOINT_BYTES = 1024 * 1024
DEFAULT_MAX_CHECKPOINT_AGE_HOURS = 48
DEFAULT_MAX_LEDGER_ENTRIES = 100_000
MAX_RECOVERY_CHECKPOINTS = 16
MAX_REPORTED_FAILURES_PER_CHECKPOINT = 20
DRILL_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$|^[a-z0-9]$"
S3_BUCKET_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,254}$")
S3_PREFIX_PART_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

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
    failure_count: int = Field(ge=0)
    failures_truncated: bool
    failures: list[RecoveryVerificationFailure]


class RecoveryDrillReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    drill_id: str = Field(pattern=DRILL_ID_PATTERN)
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
    failure_count: int = Field(ge=0)
    failures_truncated: bool
    checkpoint_results: list[RecoveryCheckpointResult]
    failures: list[RecoveryVerificationFailure]

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))


class RecoveryReportPublication(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    drill_id: str = Field(pattern=DRILL_ID_PATTERN)
    destination: str
    object_key: str
    report_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    published_at: datetime
    retention_until: datetime


class RecoveryVerificationError(RuntimeError):
    """The recovery database could not be safely inspected."""


class RecoveryReportPublicationError(RuntimeError):
    """A recovery report could not be archived immutably."""


class RecoveryReportS3Client(Protocol):
    def get_object_lock_configuration(self, **kwargs: Any) -> dict[str, Any]: ...

    def put_object(self, **kwargs: Any) -> dict[str, Any]: ...

    def head_object(self, **kwargs: Any) -> dict[str, Any]: ...


class S3ObjectLockRecoveryReportSink:
    def __init__(
        self,
        client: RecoveryReportS3Client,
        bucket: str,
        prefix: str = "aecontrol/recovery-reports",
    ) -> None:
        normalized = PurePosixPath(prefix.strip("/"))
        if (
            not S3_BUCKET_PATTERN.fullmatch(bucket)
            or not prefix.strip("/")
            or any(
                part in {"", ".", ".."} or not S3_PREFIX_PART_PATTERN.fullmatch(part)
                for part in normalized.parts
            )
        ):
            raise ValueError("S3 recovery report bucket and prefix must be normalized")
        self.client = client
        self.bucket = bucket
        self.prefix = str(normalized)

    @classmethod
    def from_environment(cls) -> S3ObjectLockRecoveryReportSink | None:
        bucket = os.getenv("AECONTROL_RECOVERY_REPORT_S3_BUCKET")
        if not bucket:
            return None
        try:
            import boto3  # type: ignore[import-untyped]
            from botocore.config import Config  # type: ignore[import-untyped]
        except ImportError as error:
            raise RuntimeError("boto3 runtime dependency is unavailable") from error
        client = boto3.client(
            "s3",
            region_name=os.getenv("AECONTROL_RECOVERY_REPORT_S3_REGION"),
            endpoint_url=os.getenv("AECONTROL_RECOVERY_REPORT_S3_ENDPOINT"),
            config=Config(
                connect_timeout=2,
                read_timeout=10,
                retries={"max_attempts": 3, "mode": "standard"},
            ),
        )
        return cls(
            client,
            bucket,
            os.getenv("AECONTROL_RECOVERY_REPORT_S3_PREFIX", "aecontrol/recovery-reports"),
        )

    def publish(
        self, report: RecoveryDrillReport, retention_days: int = 90
    ) -> RecoveryReportPublication:
        if not 1 <= retention_days <= 3650:
            raise ValueError("recovery report retention must be between 1 and 3650 days")
        try:
            configuration = self.client.get_object_lock_configuration(Bucket=self.bucket)
        except Exception as error:
            code = _s3_error_code(error, default="unknown")
            raise RecoveryReportPublicationError(
                f"could not verify S3 Object Lock configuration: {code}"
            ) from error
        if configuration.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") != "Enabled":
            raise RecoveryReportPublicationError("S3 bucket does not have Object Lock enabled")

        day = report.completed_at.astimezone(UTC).strftime("%Y/%m/%d")
        key = f"{self.prefix}/{day}/{report.drill_id}.json"
        body = report.canonical_bytes()
        digest = hashlib.sha256(body).hexdigest()
        retention_until = datetime.now(UTC) + timedelta(days=retention_days)
        try:
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=body,
                ContentType="application/json",
                ChecksumSHA256=base64.b64encode(hashlib.sha256(body).digest()).decode(),
                Metadata={"recovery-report-sha256": digest, "drill-id": report.drill_id},
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=retention_until,
                IfNoneMatch="*",
            )
        except Exception as error:
            code = _s3_error_code(error)
            if code not in {"PreconditionFailed", "412"}:
                raise RecoveryReportPublicationError(
                    f"S3 recovery report publication failed: {code}"
                ) from error
            try:
                existing = self.client.head_object(Bucket=self.bucket, Key=key)
            except Exception as head_error:
                head_code = _s3_error_code(head_error, default="unknown")
                raise RecoveryReportPublicationError(
                    f"could not verify existing S3 recovery report: {head_code}"
                ) from head_error
            metadata = existing.get("Metadata", {})
            if metadata.get("recovery-report-sha256") != digest:
                raise RecoveryReportPublicationError(
                    "S3 recovery report key already contains different bytes"
                ) from error
        return RecoveryReportPublication(
            drill_id=report.drill_id,
            destination=f"s3://{self.bucket}/{key}",
            object_key=key,
            report_sha256=digest,
            published_at=datetime.now(UTC),
            retention_until=retention_until,
        )


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


def load_recovery_checkpoint_directory(directory: Path) -> list[SignedLedgerCheckpoint]:
    try:
        metadata = directory.lstat()
    except OSError as error:
        raise ValueError(f"checkpoint directory is unavailable: {directory}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"checkpoint directory must be a non-symlink directory: {directory}")
    paths = sorted(directory.glob("*.json"))
    if not paths:
        raise ValueError(f"checkpoint directory contains no JSON envelopes: {directory}")
    if len(paths) > MAX_RECOVERY_CHECKPOINTS:
        raise ValueError(
            f"checkpoint directory contains more than {MAX_RECOVERY_CHECKPOINTS} envelopes"
        )
    return [load_recovery_checkpoint(path) for path in paths]


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

    def verify(
        self,
        checkpoints: list[SignedLedgerCheckpoint],
        *,
        drill_id: str | None = None,
    ) -> RecoveryDrillReport:
        if not checkpoints:
            raise ValueError("at least one recovery checkpoint is required")
        if len(checkpoints) > MAX_RECOVERY_CHECKPOINTS:
            raise ValueError(f"at most {MAX_RECOVERY_CHECKPOINTS} recovery checkpoints are allowed")
        resolved_drill_id = drill_id or f"drill-{uuid4().hex}"
        if not re.fullmatch(DRILL_ID_PATTERN, resolved_drill_id):
            raise ValueError("recovery drill ID must be a lowercase Kubernetes DNS label")
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
        failure_count = len(failures) + sum(result.failure_count for result in results)
        return RecoveryDrillReport(
            drill_id=resolved_drill_id,
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
            success=read_only and failure_count == 0 and len(results) == len(checkpoints),
            failure_count=failure_count,
            failures_truncated=any(result.failures_truncated for result in results),
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
        failure_count = 0

        def fail(
            code: RecoveryFailureCode,
            *,
            sequence: int | None = None,
            artifact_type: str | None = None,
            artifact_id: UUID | None = None,
        ) -> None:
            nonlocal failure_count
            failure_count += 1
            if len(failures) < MAX_REPORTED_FAILURES_PER_CHECKPOINT:
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
        if failure_count:
            return self._checkpoint_result(
                checkpoint, age_seconds, 0, 0, 0, failure_count, failures
            )

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
            return self._checkpoint_result(
                checkpoint, age_seconds, 0, 0, 0, failure_count, failures
            )

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
            checkpoint,
            age_seconds,
            len(rows),
            signed,
            unsigned,
            failure_count,
            failures,
        )

    @staticmethod
    def _checkpoint_result(
        checkpoint: SignedLedgerCheckpoint,
        age_seconds: float,
        entries_checked: int,
        signed_artifacts: int,
        unsigned_artifacts: int,
        failure_count: int,
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
            valid=failure_count == 0,
            failure_count=failure_count,
            failures_truncated=failure_count > len(failures),
            failures=failures,
        )


def _optional_string(value: object) -> str | None:
    return str(value) if value is not None else None


def _s3_error_code(error: Exception, *, default: str = "") -> str:
    response = getattr(error, "response", {})
    code = str(response.get("Error", {}).get("Code", default))
    return code if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", code) else (default or "unknown")


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
