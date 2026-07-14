from __future__ import annotations

import os
import re
from base64 import b64encode
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, cast

import google_crc32c
from google.api_core.exceptions import GoogleAPICallError, RetryError
from google.auth.exceptions import GoogleAuthError
from google.cloud import kms_v1

from aecontrol.integrity import ArtifactSigningError

GCP_KMS_KEY_VERSION_ENV = "AECONTROL_ARTIFACT_GCP_KMS_KEY_VERSION"
GCP_KMS_PROTECTION_LEVEL_ENV = "AECONTROL_ARTIFACT_GCP_KMS_PROTECTION_LEVEL"
GCP_KMS_TIMEOUT_ENV = "AECONTROL_ARTIFACT_GCP_KMS_TIMEOUT_SECONDS"
GCP_KMS_INTEGRITY_ATTEMPTS_ENV = "AECONTROL_ARTIFACT_GCP_KMS_INTEGRITY_ATTEMPTS"
GCP_KMS_ENVIRONMENT = (
    GCP_KMS_KEY_VERSION_ENV,
    GCP_KMS_PROTECTION_LEVEL_ENV,
    GCP_KMS_TIMEOUT_ENV,
    GCP_KMS_INTEGRITY_ATTEMPTS_ENV,
)
_RESOURCE_SEGMENT = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
_KEY_VERSION_PATTERN = re.compile(
    rf"^projects/(?P<project>{_RESOURCE_SEGMENT})/locations/(?P<location>{_RESOURCE_SEGMENT})/"
    rf"keyRings/(?P<key_ring>{_RESOURCE_SEGMENT})/cryptoKeys/(?P<key>{_RESOURCE_SEGMENT})/"
    r"cryptoKeyVersions/(?P<version>[1-9][0-9]*)$"
)
_PROTECTION_LEVELS = {
    "SOFTWARE",
    "HSM",
    "HSM_SINGLE_TENANT",
    "EXTERNAL",
    "EXTERNAL_VPC",
}


class GCPKMSSigningError(ArtifactSigningError):
    """Google Cloud KMS could not produce a trusted Ed25519 signature."""


@dataclass(frozen=True)
class GCPKMSConfiguration:
    key_version: str
    protection_level: str = "HSM"
    timeout_seconds: float = 5.0
    integrity_attempts: int = 3

    def __post_init__(self) -> None:
        if _KEY_VERSION_PATTERN.fullmatch(self.key_version) is None:
            raise ValueError(
                f"{GCP_KMS_KEY_VERSION_ENV} must be a full immutable CryptoKeyVersion resource name"
            )
        if self.protection_level not in _PROTECTION_LEVELS:
            raise ValueError(
                f"{GCP_KMS_PROTECTION_LEVEL_ENV} must be one of "
                f"{', '.join(sorted(_PROTECTION_LEVELS))}"
            )
        if not 0.1 <= self.timeout_seconds <= 30:
            raise ValueError(f"{GCP_KMS_TIMEOUT_ENV} must be between 0.1 and 30 seconds")
        if not 1 <= self.integrity_attempts <= 5:
            raise ValueError(f"{GCP_KMS_INTEGRITY_ATTEMPTS_ENV} must be between 1 and 5")

    @property
    def location(self) -> str:
        matched = _KEY_VERSION_PATTERN.fullmatch(self.key_version)
        assert matched is not None
        return matched.group("location")

    @property
    def key_version_sha256(self) -> str:
        return sha256(self.key_version.encode()).hexdigest()


class GCPKMSSigner:
    algorithm = "ed25519"

    def __init__(self, client: Any, configuration: GCPKMSConfiguration, key_id: str) -> None:
        self.client = client
        self.configuration = configuration
        self.key_id = key_id

    @classmethod
    def from_configuration(cls, configuration: GCPKMSConfiguration, key_id: str) -> GCPKMSSigner:
        try:
            client = kms_v1.KeyManagementServiceClient()
        except (GoogleAuthError, GoogleAPICallError, ValueError) as error:
            raise GCPKMSSigningError("Google Cloud KMS client configuration failed") from error
        return cls(client, configuration, key_id)

    def sign(self, message: bytes) -> str:
        if not 1 <= len(message) <= 4096:
            raise GCPKMSSigningError("Google Cloud KMS signing message must contain 1-4096 bytes")
        message_crc32c = google_crc32c.value(message)
        request = {
            "name": self.configuration.key_version,
            "data": message,
            "data_crc32c": message_crc32c,
        }
        for _attempt in range(self.configuration.integrity_attempts):
            try:
                response = self.client.asymmetric_sign(
                    request=request,
                    timeout=self.configuration.timeout_seconds,
                )
            except (GoogleAPICallError, GoogleAuthError, RetryError) as error:
                raise GCPKMSSigningError("Google Cloud KMS signing request failed") from error
            if getattr(response, "name", None) != self.configuration.key_version:
                raise GCPKMSSigningError("Google Cloud KMS returned an unexpected key version")
            if self._protection_level(response) != self.configuration.protection_level:
                raise GCPKMSSigningError("Google Cloud KMS returned an unexpected protection level")
            signature = getattr(response, "signature", None)
            signature_crc32c = getattr(response, "signature_crc32c", None)
            verified_data_crc32c = getattr(response, "verified_data_crc32c", False)
            if isinstance(signature, bytes):
                signature_checksum_valid = google_crc32c.value(signature) == signature_crc32c
            else:
                signature_checksum_valid = False
            if (
                verified_data_crc32c is True
                and signature_checksum_valid
                and isinstance(signature, bytes)
            ):
                if len(signature) != 64:
                    raise GCPKMSSigningError(
                        "Google Cloud KMS returned an invalid Ed25519 signature"
                    )
                return b64encode(signature).decode()
        raise GCPKMSSigningError(
            "Google Cloud KMS signing response failed CRC32C integrity verification"
        )

    @staticmethod
    def _protection_level(response: object) -> str | None:
        observed = getattr(response, "protection_level", None)
        try:
            return cast(str, kms_v1.ProtectionLevel(observed).name)
        except (TypeError, ValueError):
            return None


def gcp_kms_configuration_from_environment() -> GCPKMSConfiguration | None:
    configured = {name: os.getenv(name) for name in GCP_KMS_ENVIRONMENT}
    if not any(value is not None for value in configured.values()):
        return None
    key_version = configured[GCP_KMS_KEY_VERSION_ENV]
    if not key_version:
        raise ValueError(
            f"{GCP_KMS_KEY_VERSION_ENV} is required when Google Cloud KMS signing is configured"
        )
    protection_level = configured[GCP_KMS_PROTECTION_LEVEL_ENV] or "HSM"
    raw_timeout = configured[GCP_KMS_TIMEOUT_ENV] or "5"
    raw_attempts = configured[GCP_KMS_INTEGRITY_ATTEMPTS_ENV] or "3"
    try:
        timeout = float(raw_timeout)
    except ValueError as error:
        raise ValueError(f"{GCP_KMS_TIMEOUT_ENV} must be a number") from error
    try:
        integrity_attempts = int(raw_attempts)
    except ValueError as error:
        raise ValueError(f"{GCP_KMS_INTEGRITY_ATTEMPTS_ENV} must be an integer") from error
    return GCPKMSConfiguration(
        key_version=key_version,
        protection_level=protection_level,
        timeout_seconds=timeout,
        integrity_attempts=integrity_attempts,
    )
