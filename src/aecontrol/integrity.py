from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from base64 import b64decode, b64encode
from binascii import Error as Base64Error
from typing import Any, Protocol
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIGNING_KEYS_ENV = "AECONTROL_ARTIFACT_SIGNING_KEYS"
SIGNING_KEY_ID_ENV = "AECONTROL_ARTIFACT_SIGNING_KEY_ID"
SIGNING_ALGORITHM_ENV = "AECONTROL_ARTIFACT_SIGNING_ALGORITHM"
ED25519_PRIVATE_KEYS_ENV = "AECONTROL_ARTIFACT_ED25519_PRIVATE_KEYS"
ED25519_PUBLIC_KEYS_ENV = "AECONTROL_ARTIFACT_ED25519_PUBLIC_KEYS"
HMAC_SHA256 = "hmac-sha256"
ED25519 = "ed25519"
SIGNATURE_ALGORITHMS = frozenset({HMAC_SHA256, ED25519})
LEDGER_GENESIS_SHA256 = "0" * 64
_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_SIGNATURE_CONTEXT = "aecontrol:v1"


class ArtifactSigner(Protocol):
    algorithm: str
    key_id: str

    def sign(self, message: bytes) -> str: ...


def artifact_digest(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(
        _normalize_json(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def ledger_entry_digest(
    tenant_id: str,
    sequence: int,
    artifact_type: str,
    artifact_id: UUID,
    payload_sha256: str,
    signature_algorithm: str | None,
    signing_key_id: str | None,
    signature: str | None,
    previous_entry_sha256: str,
) -> str:
    return artifact_digest(
        {
            "tenant_id": tenant_id,
            "sequence": sequence,
            "artifact_type": artifact_type,
            "artifact_id": str(artifact_id),
            "payload_sha256": payload_sha256,
            "signature_algorithm": signature_algorithm,
            "signing_key_id": signing_key_id,
            "signature": signature,
            "previous_entry_sha256": previous_entry_sha256,
        }
    )


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


class ArtifactSigningError(RuntimeError):
    """A remote signer could not produce a locally verifiable signature."""


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
        algorithm: str | None = None,
    ) -> None:
        if reason == "missing_signing_key":
            message = (
                f"{artifact_type} {artifact_id} requires unavailable artifact verification key "
                f"{signing_key_id!r} for {algorithm or 'unknown algorithm'}"
            )
        elif reason == "incomplete_signature":
            message = f"{artifact_type} {artifact_id} has incomplete signature metadata"
        else:
            message = (
                f"{artifact_type} {artifact_id} failed "
                f"{algorithm or 'artifact'} authenticity verification"
            )
        super().__init__(message)
        self.artifact_type = artifact_type
        self.artifact_id = artifact_id
        self.signing_key_id = signing_key_id
        self.reason = reason
        self.algorithm = algorithm


class ArtifactKeyring:
    """External signing keys used to sign new artifacts and verify historical ones."""

    def __init__(
        self,
        keys: dict[str, bytes] | None = None,
        active_key_id: str | None = None,
        *,
        active_algorithm: str | None = None,
        ed25519_private_keys: dict[str, bytes] | None = None,
        ed25519_public_keys: dict[str, bytes] | None = None,
        remote_signer: ArtifactSigner | None = None,
    ) -> None:
        hmac_keys = dict(keys or {})
        private_keys = dict(ed25519_private_keys or {})
        public_keys = dict(ed25519_public_keys or {})
        if active_key_id is not None and active_algorithm is None and hmac_keys:
            active_algorithm = HMAC_SHA256
        for key_id in hmac_keys | private_keys | public_keys:
            if not _KEY_ID_PATTERN.fullmatch(key_id):
                raise ValueError(f"invalid artifact signing key ID: {key_id!r}")
        for key_id, key in hmac_keys.items():
            if len(key) < 32:
                raise ValueError(f"artifact signing key {key_id!r} must contain at least 32 bytes")

        self._hmac_keys = hmac_keys
        self._ed25519_private_keys: dict[str, Ed25519PrivateKey] = {}
        self._ed25519_public_keys: dict[str, Ed25519PublicKey] = {}
        for key_id, key in private_keys.items():
            if len(key) != 32:
                raise ValueError(f"Ed25519 private key {key_id!r} must contain exactly 32 bytes")
            private_key = Ed25519PrivateKey.from_private_bytes(key)
            self._ed25519_private_keys[key_id] = private_key
            self._ed25519_public_keys[key_id] = private_key.public_key()
        for key_id, key in public_keys.items():
            if len(key) != 32:
                raise ValueError(f"Ed25519 public key {key_id!r} must contain exactly 32 bytes")
            public_key = Ed25519PublicKey.from_public_bytes(key)
            derived = self._ed25519_public_keys.get(key_id)
            if derived is not None and not hmac.compare_digest(
                _raw_public_key(derived), _raw_public_key(public_key)
            ):
                raise ValueError(f"Ed25519 public key {key_id!r} does not match its private key")
            self._ed25519_public_keys[key_id] = public_key

        if (active_key_id is None) != (active_algorithm is None):
            raise ValueError("active artifact signing key ID and algorithm must be set together")
        if active_algorithm not in SIGNATURE_ALGORITHMS | {None}:
            raise ValueError(f"unsupported artifact signing algorithm: {active_algorithm!r}")
        if (
            active_key_id is not None
            and active_algorithm == HMAC_SHA256
            and active_key_id not in self._hmac_keys
        ):
            raise ValueError(
                f"active artifact signing key {active_key_id!r} is not in the keyring "
                f"for {HMAC_SHA256}"
            )
        if (
            active_key_id is not None
            and active_algorithm == ED25519
            and active_key_id not in self._ed25519_private_keys
            and remote_signer is None
        ):
            raise ValueError(
                f"active artifact signing key {active_key_id!r} has no Ed25519 private key"
            )
        if remote_signer is not None:
            if (
                active_key_id != remote_signer.key_id
                or active_algorithm != remote_signer.algorithm
                or active_algorithm != ED25519
            ):
                raise ValueError("remote signer must match the active Ed25519 signing key")
            if active_key_id in self._ed25519_private_keys:
                raise ValueError(
                    "remote signer cannot be combined with an active local private key"
                )
            if active_key_id not in self._ed25519_public_keys:
                raise ValueError(
                    "remote signer requires its active Ed25519 public verification key"
                )
        self.active_key_id = active_key_id
        self.active_algorithm = active_algorithm
        self._remote_signer = remote_signer

    @classmethod
    def from_environment(cls) -> ArtifactKeyring | None:
        encoded_keys = os.getenv(SIGNING_KEYS_ENV)
        active_key_id = os.getenv(SIGNING_KEY_ID_ENV)
        active_algorithm = os.getenv(SIGNING_ALGORITHM_ENV)
        encoded_private_keys = os.getenv(ED25519_PRIVATE_KEYS_ENV)
        encoded_public_keys = os.getenv(ED25519_PUBLIC_KEYS_ENV)
        from aecontrol.aws_kms import AWSKMSSigner, aws_kms_configuration_from_environment
        from aecontrol.vault import VaultTransitSigner, vault_configuration_from_environment

        vault = vault_configuration_from_environment()
        aws_kms = aws_kms_configuration_from_environment()
        if vault is not None and aws_kms is not None:
            raise ValueError("Vault Transit and AWS KMS artifact signing are mutually exclusive")
        new_configuration = any(
            value is not None
            for value in (
                active_algorithm,
                encoded_private_keys,
                encoded_public_keys,
                vault,
                aws_kms,
            )
        )
        if not new_configuration and encoded_keys is None and active_key_id is None:
            return None
        if not new_configuration:
            if not encoded_keys or not active_key_id:
                raise ValueError(
                    f"{SIGNING_KEYS_ENV} and {SIGNING_KEY_ID_ENV} must be set together"
                )
            return cls(
                _decode_key_map(SIGNING_KEYS_ENV, encoded_keys),
                active_key_id,
                active_algorithm=HMAC_SHA256,
            )

        if (active_key_id is None) != (active_algorithm is None):
            raise ValueError(
                f"{SIGNING_KEY_ID_ENV} and {SIGNING_ALGORITHM_ENV} must be set together"
            )
        if vault is not None and (active_key_id is None or active_algorithm != ED25519):
            raise ValueError("Vault Transit requires an active Ed25519 signing key configuration")
        if aws_kms is not None and (active_key_id is None or active_algorithm != ED25519):
            raise ValueError("AWS KMS requires an active Ed25519 signing key configuration")
        public_keys = _decode_optional_key_map(ED25519_PUBLIC_KEYS_ENV, encoded_public_keys)
        remote_signer: ArtifactSigner | None = None
        if vault is not None and active_key_id is not None:
            remote_signer = VaultTransitSigner(vault, active_key_id)
        elif aws_kms is not None and active_key_id is not None:
            remote_signer = AWSKMSSigner.from_configuration(aws_kms, active_key_id)
        return cls(
            _decode_optional_key_map(SIGNING_KEYS_ENV, encoded_keys),
            active_key_id,
            active_algorithm=active_algorithm,
            ed25519_private_keys=_decode_optional_key_map(
                ED25519_PRIVATE_KEYS_ENV, encoded_private_keys
            ),
            ed25519_public_keys=public_keys,
            remote_signer=remote_signer,
        )

    def sign(self, artifact_type: str, artifact_id: UUID, payload_sha256: str) -> str:
        if self.active_key_id is None or self.active_algorithm is None:
            raise ValueError("artifact keyring has no active signing key")
        message = _signature_message(artifact_type, artifact_id, payload_sha256)
        if self.active_algorithm == HMAC_SHA256:
            return hmac.new(
                self._hmac_keys[self.active_key_id], message, hashlib.sha256
            ).hexdigest()
        if self._remote_signer is not None:
            signature = self._remote_signer.sign(message)
            if not self.verify(
                self.active_algorithm,
                self.active_key_id,
                artifact_type,
                artifact_id,
                payload_sha256,
                signature,
            ):
                raise ArtifactSigningError(
                    "remote artifact signer returned a signature that failed local verification"
                )
            return signature
        return b64encode(self._ed25519_private_keys[self.active_key_id].sign(message)).decode()

    def verify(
        self,
        algorithm: str,
        key_id: str,
        artifact_type: str,
        artifact_id: UUID,
        payload_sha256: str,
        signature: str,
    ) -> bool:
        message = _signature_message(artifact_type, artifact_id, payload_sha256)
        if algorithm == HMAC_SHA256:
            hmac_key = self._hmac_keys.get(key_id)
            if hmac_key is None:
                raise KeyError(key_id)
            expected = hmac.new(hmac_key, message, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature)
        if algorithm != ED25519:
            raise ValueError(f"unsupported artifact signature algorithm: {algorithm!r}")
        public_key = self._ed25519_public_keys.get(key_id)
        if public_key is None:
            raise KeyError(key_id)
        try:
            decoded = b64decode(signature, validate=True)
            public_key.verify(decoded, message)
        except (Base64Error, InvalidSignature, ValueError):
            return False
        return True


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return private_bytes, _raw_public_key(private_key.public_key())


def _raw_public_key(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _decode_optional_key_map(name: str, value: str | None) -> dict[str, bytes]:
    return {} if value is None else _decode_key_map(name, value)


def _decode_key_map(name: str, value: str) -> dict[str, bytes]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError(f"{name} must be a JSON object") from error
    if not isinstance(payload, dict) or not payload:
        raise ValueError(f"{name} must be a non-empty JSON object")
    keys: dict[str, bytes] = {}
    for key_id, encoded_key in payload.items():
        if not isinstance(key_id, str) or not isinstance(encoded_key, str):
            raise ValueError(f"{name} must map key IDs to base64 strings")
        try:
            keys[key_id] = b64decode(encoded_key, validate=True)
        except (Base64Error, ValueError) as error:
            raise ValueError(f"artifact signing key {key_id!r} must be valid base64") from error
    return keys


def _signature_message(artifact_type: str, artifact_id: UUID, payload_sha256: str) -> bytes:
    return f"{_SIGNATURE_CONTEXT}:{artifact_type}:{artifact_id}:{payload_sha256}".encode()


def verify_digest(expected: str, payload: Any) -> str:
    actual = artifact_digest(payload)
    if not hmac.compare_digest(expected, actual):
        raise ValueError(actual)
    return actual
