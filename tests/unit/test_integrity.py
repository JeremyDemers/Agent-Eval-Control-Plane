from __future__ import annotations

import base64
import json
from uuid import uuid4

import pytest

from aecontrol.integrity import (
    ED25519,
    ED25519_PRIVATE_KEYS_ENV,
    ED25519_PUBLIC_KEYS_ENV,
    HMAC_SHA256,
    SIGNING_ALGORITHM_ENV,
    SIGNING_KEY_ID_ENV,
    SIGNING_KEYS_ENV,
    ArtifactKeyring,
    artifact_digest,
    generate_ed25519_keypair,
    ledger_entry_digest,
    verify_digest,
)


def test_artifact_digest_is_canonical_and_verifiable() -> None:
    first = {"unicode": "caf\u00e9", "nested": {"b": 2, "a": 1}}
    reordered = {"nested": {"a": 1, "b": 2}, "unicode": "caf\u00e9"}

    digest = artifact_digest(first)

    assert digest == artifact_digest(reordered)
    assert artifact_digest({"zero": -0.0}) == artifact_digest({"zero": 0.0})
    assert len(digest) == 64
    assert verify_digest(digest, reordered) == digest
    with pytest.raises(ValueError):
        verify_digest("0" * 64, first)
    with pytest.raises(ValueError):
        artifact_digest({"invalid": float("nan")})


def test_ledger_digest_binds_tenant_sequence_envelope_and_previous_hash() -> None:
    artifact_id = uuid4()
    arguments = (
        "tenant-a",
        1,
        "run",
        artifact_id,
        "a" * 64,
        ED25519,
        "attestor",
        "signature",
        "0" * 64,
    )

    digest = ledger_entry_digest(*arguments)

    assert len(digest) == 64
    assert digest == ledger_entry_digest(*arguments)
    assert digest != ledger_entry_digest("tenant-b", *arguments[1:])
    assert digest != ledger_entry_digest(*arguments[:-1], "f" * 64)


def test_keyring_signatures_bind_artifact_identity_type_and_digest() -> None:
    artifact_id = uuid4()
    keyring = ArtifactKeyring({"current": b"a" * 32}, "current")
    digest = "1" * 64

    signature = keyring.sign("run", artifact_id, digest)

    assert len(signature) == 64
    assert keyring.active_algorithm == HMAC_SHA256
    assert keyring.verify(HMAC_SHA256, "current", "run", artifact_id, digest, signature)
    assert not keyring.verify(HMAC_SHA256, "current", "comparison", artifact_id, digest, signature)
    assert not keyring.verify(HMAC_SHA256, "current", "run", uuid4(), digest, signature)
    assert not keyring.verify(HMAC_SHA256, "current", "run", artifact_id, "2" * 64, signature)
    with pytest.raises(KeyError):
        keyring.verify(HMAC_SHA256, "retired", "run", artifact_id, digest, signature)


def test_ed25519_signatures_support_public_key_only_verification() -> None:
    private_key, public_key = generate_ed25519_keypair()
    signer = ArtifactKeyring(
        active_key_id="release-2026-07",
        active_algorithm=ED25519,
        ed25519_private_keys={"release-2026-07": private_key},
    )
    verifier = ArtifactKeyring(ed25519_public_keys={"release-2026-07": public_key})
    artifact_id = uuid4()
    digest = "d" * 64

    signature = signer.sign("run", artifact_id, digest)

    assert len(base64.b64decode(signature, validate=True)) == 64
    assert verifier.active_key_id is None
    assert verifier.verify(ED25519, "release-2026-07", "run", artifact_id, digest, signature)
    assert not verifier.verify(
        ED25519, "release-2026-07", "comparison", artifact_id, digest, signature
    )
    with pytest.raises(ValueError, match="no active signing key"):
        verifier.sign("run", artifact_id, digest)


def test_ed25519_key_configuration_fails_closed() -> None:
    private_key, public_key = generate_ed25519_keypair()
    _, unrelated_public_key = generate_ed25519_keypair()

    with pytest.raises(ValueError, match=r"private key.*exactly 32 bytes"):
        ArtifactKeyring(
            active_key_id="attestor",
            active_algorithm=ED25519,
            ed25519_private_keys={"attestor": private_key[:-1]},
        )
    with pytest.raises(ValueError, match="does not match its private key"):
        ArtifactKeyring(
            active_key_id="attestor",
            active_algorithm=ED25519,
            ed25519_private_keys={"attestor": private_key},
            ed25519_public_keys={"attestor": unrelated_public_key},
        )
    with pytest.raises(ValueError, match="has no Ed25519 private key"):
        ArtifactKeyring(
            active_key_id="attestor",
            active_algorithm=ED25519,
            ed25519_public_keys={"attestor": public_key},
        )


def test_keyring_loads_base64_keys_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    encoded = base64.b64encode(b"k" * 32).decode()
    monkeypatch.setenv(SIGNING_KEY_ID_ENV, "2026-07")
    monkeypatch.setenv(SIGNING_KEYS_ENV, json.dumps({"2026-07": encoded}))

    keyring = ArtifactKeyring.from_environment()

    assert keyring is not None
    assert keyring.active_key_id == "2026-07"
    assert keyring.active_algorithm == HMAC_SHA256
    artifact_id = uuid4()
    signature = keyring.sign("run", artifact_id, "a" * 64)
    assert keyring.verify(HMAC_SHA256, "2026-07", "run", artifact_id, "a" * 64, signature)


def test_keyring_loads_ed25519_signer_and_public_verifier_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key, public_key = generate_ed25519_keypair()
    encoded_private = base64.b64encode(private_key).decode()
    encoded_public = base64.b64encode(public_key).decode()
    monkeypatch.setenv(SIGNING_KEY_ID_ENV, "attestor")
    monkeypatch.setenv(SIGNING_ALGORITHM_ENV, ED25519)
    monkeypatch.setenv(ED25519_PRIVATE_KEYS_ENV, json.dumps({"attestor": encoded_private}))
    monkeypatch.setenv(ED25519_PUBLIC_KEYS_ENV, json.dumps({"attestor": encoded_public}))

    signer = ArtifactKeyring.from_environment()

    assert signer is not None
    artifact_id = uuid4()
    signature = signer.sign("run", artifact_id, "a" * 64)
    monkeypatch.delenv(SIGNING_KEY_ID_ENV)
    monkeypatch.delenv(SIGNING_ALGORITHM_ENV)
    monkeypatch.delenv(ED25519_PRIVATE_KEYS_ENV)
    verifier = ArtifactKeyring.from_environment()
    assert verifier is not None
    assert verifier.verify(ED25519, "attestor", "run", artifact_id, "a" * 64, signature)


def test_keyring_is_optional_when_environment_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(SIGNING_KEY_ID_ENV, raising=False)
    monkeypatch.delenv(SIGNING_KEYS_ENV, raising=False)
    monkeypatch.delenv(SIGNING_ALGORITHM_ENV, raising=False)
    monkeypatch.delenv(ED25519_PRIVATE_KEYS_ENV, raising=False)
    monkeypatch.delenv(ED25519_PUBLIC_KEYS_ENV, raising=False)
    assert ArtifactKeyring.from_environment() is None


@pytest.mark.parametrize(
    ("active_key_id", "encoded_keys", "message"),
    [
        ("current", None, "must be set together"),
        (None, "{}", "must be set together"),
        ("current", "not-json", "must be a JSON object"),
        ("current", "[]", "must be a non-empty JSON object"),
        ("current", "{}", "must be a non-empty JSON object"),
        ("current", '{"current": 1}', "must map key IDs to base64 strings"),
        ("current", '{"current": "%%%"}', "must be valid base64"),
        (
            "current",
            json.dumps({"current": base64.b64encode(b"short").decode()}),
            "at least 32 bytes",
        ),
        (
            "missing",
            json.dumps({"current": base64.b64encode(b"k" * 32).decode()}),
            "is not in the keyring",
        ),
        (
            "bad key id",
            json.dumps({"bad key id": base64.b64encode(b"k" * 32).decode()}),
            "invalid artifact signing key ID",
        ),
    ],
)
def test_invalid_keyring_environment_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    active_key_id: str | None,
    encoded_keys: str | None,
    message: str,
) -> None:
    if active_key_id is None:
        monkeypatch.delenv(SIGNING_KEY_ID_ENV, raising=False)
    else:
        monkeypatch.setenv(SIGNING_KEY_ID_ENV, active_key_id)
    if encoded_keys is None:
        monkeypatch.delenv(SIGNING_KEYS_ENV, raising=False)
    else:
        monkeypatch.setenv(SIGNING_KEYS_ENV, encoded_keys)

    with pytest.raises(ValueError, match=message):
        ArtifactKeyring.from_environment()
