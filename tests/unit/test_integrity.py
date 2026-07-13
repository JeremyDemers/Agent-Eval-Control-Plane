from __future__ import annotations

import base64
import json
from uuid import uuid4

import pytest

from aecontrol.integrity import (
    SIGNING_KEY_ID_ENV,
    SIGNING_KEYS_ENV,
    ArtifactKeyring,
    artifact_digest,
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


def test_keyring_signatures_bind_artifact_identity_type_and_digest() -> None:
    artifact_id = uuid4()
    keyring = ArtifactKeyring({"current": b"a" * 32}, "current")
    digest = "1" * 64

    signature = keyring.sign("run", artifact_id, digest)

    assert len(signature) == 64
    assert keyring.verify("current", "run", artifact_id, digest, signature)
    assert not keyring.verify("current", "comparison", artifact_id, digest, signature)
    assert not keyring.verify("current", "run", uuid4(), digest, signature)
    assert not keyring.verify("current", "run", artifact_id, "2" * 64, signature)
    with pytest.raises(KeyError):
        keyring.verify("retired", "run", artifact_id, digest, signature)


def test_keyring_loads_base64_keys_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    encoded = base64.b64encode(b"k" * 32).decode()
    monkeypatch.setenv(SIGNING_KEY_ID_ENV, "2026-07")
    monkeypatch.setenv(SIGNING_KEYS_ENV, json.dumps({"2026-07": encoded}))

    keyring = ArtifactKeyring.from_environment()

    assert keyring is not None
    assert keyring.active_key_id == "2026-07"
    artifact_id = uuid4()
    signature = keyring.sign("run", artifact_id, "a" * 64)
    assert keyring.verify("2026-07", "run", artifact_id, "a" * 64, signature)


def test_keyring_is_optional_when_environment_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(SIGNING_KEY_ID_ENV, raising=False)
    monkeypatch.delenv(SIGNING_KEYS_ENV, raising=False)
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
