from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import psycopg
from psycopg import sql

from aecontrol.api import DEFAULT_DATABASE_URL
from aecontrol.integrity import ED25519, ArtifactKeyring, generate_ed25519_keypair
from aecontrol.models import EvaluationRun
from aecontrol.recovery import RecoveryVerifier
from aecontrol.store import ArtifactStore
from aecontrol.tenancy import bind_tenant, reset_tenant


def _run() -> EvaluationRun:
    now = datetime.now(UTC)
    return EvaluationRun(
        suite_name="recovery-drill",
        dataset_name="restore-canary",
        dataset_version="sha256:restore-canary",
        agent_version="recovery-verifier",
        started_at=now,
        completed_at=now,
        case_results=[],
    )


def test_recovery_verifier_audits_signed_checkpoint_and_detects_source_deletion() -> None:
    database_url = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)
    schema = f"test_{uuid4().hex}"
    private_key, public_key = generate_ed25519_keypair()
    signer = ArtifactKeyring(
        active_key_id="recovery-key",
        active_algorithm=ED25519,
        ed25519_private_keys={"recovery-key": private_key},
    )
    verifier_keyring = ArtifactKeyring(ed25519_public_keys={"recovery-key": public_key})
    token = bind_tenant("recovery-tenant")
    run = _run()
    try:
        store = ArtifactStore(database_url, schema=schema, keyring=signer)
        store.save_run(run)
        checkpoint = store.create_ledger_checkpoint(retention_days=30)
        store.close()

        verifier = RecoveryVerifier(
            database_url,
            schema=schema,
            keyring=verifier_keyring,
            max_checkpoint_age_hours=24,
        )
        valid = verifier.verify([checkpoint])

        assert valid.success is True
        assert valid.transaction_read_only is True
        assert valid.recovery_in_progress is False
        assert valid.observed_schema_version == 18
        assert valid.checkpoints_valid == 1
        assert valid.entries_checked == 1
        assert valid.checkpoint_results[0].signed_artifacts == 1
        assert valid.failures == []

        with psycopg.connect(database_url) as connection:
            connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
            connection.execute("SELECT set_config('aecontrol.tenant_id', 'recovery-tenant', true)")
            connection.execute("DELETE FROM evaluation_runs WHERE run_id = %s", (run.run_id,))

        invalid = verifier.verify([checkpoint])
        assert invalid.success is False
        assert invalid.checkpoint_results[0].valid is False
        assert "artifact_missing" in {failure.code for failure in invalid.failures}
    finally:
        reset_tenant(token)
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_recovery_verifier_reports_old_schema_without_migrating_it() -> None:
    database_url = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)
    schema = f"test_{uuid4().hex}"
    private_key, public_key = generate_ed25519_keypair()
    signer = ArtifactKeyring(
        active_key_id="recovery-key",
        active_algorithm=ED25519,
        ed25519_private_keys={"recovery-key": private_key},
    )
    token = bind_tenant("recovery-tenant")
    try:
        store = ArtifactStore(database_url, schema=schema, keyring=signer)
        checkpoint = store.create_ledger_checkpoint(retention_days=30)
        store.close()
        with psycopg.connect(database_url) as connection:
            connection.execute(
                sql.SQL("UPDATE {}.schema_metadata SET version = 17").format(sql.Identifier(schema))
            )

        report = RecoveryVerifier(
            database_url,
            schema=schema,
            keyring=ArtifactKeyring(ed25519_public_keys={"recovery-key": public_key}),
        ).verify([checkpoint])

        assert report.success is False
        assert report.observed_schema_version == 17
        assert report.checkpoints_checked == 0
        assert [failure.code for failure in report.failures] == ["schema_version"]
        with psycopg.connect(database_url) as connection:
            version = connection.execute(
                sql.SQL("SELECT version FROM {}.schema_metadata").format(sql.Identifier(schema))
            ).fetchone()
        assert version == (17,)
    finally:
        reset_tenant(token)
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )
