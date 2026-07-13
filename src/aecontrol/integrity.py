from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from base64 import b64decode
from binascii import Error as Base64Error
from typing import Any
from uuid import UUID

SIGNING_KEYS_ENV = "AECONTROL_ARTIFACT_SIGNING_KEYS"
SIGNING_KEY_ID_ENV = "AECONTROL_ARTIFACT_SIGNING_KEY_ID"
_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_SIGNATURE_CONTEXT = "aecontrol:v1"


def artifact_digest(payload: Any) -> str:
    canonical = json.dumps(
        _normalize_json(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _normalize_json(value: Any) -> Any:
    if isinstance(value, float) and value == 0:
        return 0.0
    if isinstance(value, dict):
        return {key: _normalize_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_json(item) for item in value]
    return value


class ArtifactVerificationError(RuntimeError):
    """A persisted artifact cannot be trusted and must not be returned."""


class ArtifactIntegrityError(ArtifactVerificationError):
    def __init__(
        self,
        artifact_type: str,
        artifact_id: UUID,
        expected_sha256: str,
        actual_sha256: str,
    ) -> None:
        super().__init__(f"{artifact_type} {artifact_id} failed SHA-256 integrity verification")
        self.artifact_type = artifact_type
        self.artifact_id = artifact_id
        self.expected_sha256 = expected_sha256
        self.actual_sha256 = actual_sha256


class ArtifactAuthenticityError(ArtifactVerificationError):
    def __init__(
        self,
        artifact_type: str,
        artifact_id: UUID,
        signing_key_id: str | None,
        reason: str,
    ) -> None:
        if reason == "missing_signing_key":
            message = (
                f"{artifact_type} {artifact_id} requires unavailable artifact signing key "
                f"{signing_key_id!r}"
            )
        elif reason == "incomplete_signature":
            message = f"{artifact_type} {artifact_id} has incomplete signature metadata"
        else:
            message = f"{artifact_type} {artifact_id} failed HMAC-SHA256 authenticity verification"
        super().__init__(message)
        self.artifact_type = artifact_type
        self.artifact_id = artifact_id
        self.signing_key_id = signing_key_id
        self.reason = reason


class ArtifactKeyring:
    """External HMAC keys used to sign new artifacts and verify historical ones."""

    def __init__(self, keys: dict[str, bytes], active_key_id: str) -> None:
        if active_key_id not in keys:
            raise ValueError(f"active artifact signing key {active_key_id!r} is not in the keyring")
        for key_id, key in keys.items():
            if not _KEY_ID_PATTERN.fullmatch(key_id):
                raise ValueError(f"invalid artifact signing key ID: {key_id!r}")
            if len(key) < 32:
                raise ValueError(f"artifact signing key {key_id!r} must contain at least 32 bytes")
        self._keys = dict(keys)
        self.active_key_id = active_key_id

    @classmethod
    def from_environment(cls) -> ArtifactKeyring | None:
        encoded_keys = os.getenv(SIGNING_KEYS_ENV)
        active_key_id = os.getenv(SIGNING_KEY_ID_ENV)
        if encoded_keys is None and active_key_id is None:
            return None
        if not encoded_keys or not active_key_id:
            raise ValueError(f"{SIGNING_KEYS_ENV} and {SIGNING_KEY_ID_ENV} must be set together")
        try:
            payload = json.loads(encoded_keys)
        except json.JSONDecodeError as error:
            raise ValueError(f"{SIGNING_KEYS_ENV} must be a JSON object") from error
        if not isinstance(payload, dict) or not payload:
            raise ValueError(f"{SIGNING_KEYS_ENV} must be a non-empty JSON object")
        keys: dict[str, bytes] = {}
        for key_id, encoded_key in payload.items():
            if not isinstance(key_id, str) or not isinstance(encoded_key, str):
                raise ValueError(f"{SIGNING_KEYS_ENV} must map key IDs to base64 strings")
            try:
                keys[key_id] = b64decode(encoded_key, validate=True)
            except (Base64Error, ValueError) as error:
                raise ValueError(f"artifact signing key {key_id!r} must be valid base64") from error
        return cls(keys, active_key_id)

    def sign(self, artifact_type: str, artifact_id: UUID, payload_sha256: str) -> str:
        return hmac.new(
            self._keys[self.active_key_id],
            _signature_message(artifact_type, artifact_id, payload_sha256),
            hashlib.sha256,
        ).hexdigest()

    def verify(
        self,
        key_id: str,
        artifact_type: str,
        artifact_id: UUID,
        payload_sha256: str,
        signature: str,
    ) -> bool:
        key = self._keys.get(key_id)
        if key is None:
            raise KeyError(key_id)
        expected = hmac.new(
            key,
            _signature_message(artifact_type, artifact_id, payload_sha256),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)


def _signature_message(artifact_type: str, artifact_id: UUID, payload_sha256: str) -> bytes:
    return f"{_SIGNATURE_CONTEXT}:{artifact_type}:{artifact_id}:{payload_sha256}".encode()


def verify_digest(expected: str, payload: Any) -> str:
    actual = artifact_digest(payload)
    if not hmac.compare_digest(expected, actual):
        raise ValueError(actual)
    return actual
