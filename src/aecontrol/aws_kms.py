from __future__ import annotations

import os
import re
from base64 import b64encode
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]

from aecontrol.integrity import ArtifactSigningError

AWS_KMS_KEY_ARN_ENV = "AECONTROL_ARTIFACT_AWS_KMS_KEY_ARN"
AWS_KMS_TIMEOUT_ENV = "AECONTROL_ARTIFACT_AWS_KMS_TIMEOUT_SECONDS"
AWS_KMS_ENVIRONMENT = (AWS_KMS_KEY_ARN_ENV, AWS_KMS_TIMEOUT_ENV)
AWS_KMS_KEY_SPEC = "ECC_NIST_EDWARDS25519"
AWS_KMS_SIGNING_ALGORITHM = "ED25519_SHA_512"
_KEY_ARN_PATTERN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):kms:([a-z0-9-]{3,32}):([0-9]{12}):"
    r"key/([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})$"
)


class AWSKMSSigningError(ArtifactSigningError):
    """AWS KMS could not produce a trusted Ed25519 signature."""


@dataclass(frozen=True)
class AWSKMSConfiguration:
    key_arn: str
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if _KEY_ARN_PATTERN.fullmatch(self.key_arn) is None:
            raise ValueError(
                f"{AWS_KMS_KEY_ARN_ENV} must be a full asymmetric KMS key ARN, not an alias"
            )
        if not 0.1 <= self.timeout_seconds <= 30:
            raise ValueError(f"{AWS_KMS_TIMEOUT_ENV} must be between 0.1 and 30 seconds")

    @property
    def region(self) -> str:
        matched = _KEY_ARN_PATTERN.fullmatch(self.key_arn)
        assert matched is not None
        return matched.group(2)

    @property
    def key_arn_sha256(self) -> str:
        return sha256(self.key_arn.encode()).hexdigest()


class AWSKMSSigner:
    algorithm = "ed25519"

    def __init__(self, client: Any, configuration: AWSKMSConfiguration, key_id: str) -> None:
        self.client = client
        self.configuration = configuration
        self.key_id = key_id

    @classmethod
    def from_configuration(
        cls, configuration: AWSKMSConfiguration, key_id: str
    ) -> AWSKMSSigner:
        try:
            import boto3  # type: ignore[import-untyped]
            from botocore.config import Config  # type: ignore[import-untyped]
        except ImportError as error:
            raise RuntimeError("boto3 runtime dependency is unavailable") from error
        client = boto3.client(
            "kms",
            region_name=configuration.region,
            config=Config(
                connect_timeout=configuration.timeout_seconds,
                read_timeout=configuration.timeout_seconds,
                retries={"max_attempts": 3, "mode": "standard"},
            ),
        )
        return cls(client, configuration, key_id)

    def sign(self, message: bytes) -> str:
        if not 1 <= len(message) <= 4096:
            raise AWSKMSSigningError("AWS KMS signing message must contain 1-4096 bytes")
        try:
            response = self.client.sign(
                KeyId=self.configuration.key_arn,
                Message=message,
                MessageType="RAW",
                SigningAlgorithm=AWS_KMS_SIGNING_ALGORITHM,
            )
        except (BotoCoreError, ClientError) as error:
            raise AWSKMSSigningError("AWS KMS signing request failed") from error
        if not isinstance(response, dict):
            raise AWSKMSSigningError("AWS KMS returned an invalid signing response")
        if response.get("KeyId") != self.configuration.key_arn:
            raise AWSKMSSigningError("AWS KMS returned an unexpected signing key")
        if response.get("SigningAlgorithm") != AWS_KMS_SIGNING_ALGORITHM:
            raise AWSKMSSigningError("AWS KMS returned an unexpected signing algorithm")
        signature = response.get("Signature")
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise AWSKMSSigningError("AWS KMS returned an invalid Ed25519 signature")
        return b64encode(signature).decode()


def aws_kms_configuration_from_environment() -> AWSKMSConfiguration | None:
    configured = {name: os.getenv(name) for name in AWS_KMS_ENVIRONMENT}
    if not any(value is not None for value in configured.values()):
        return None
    key_arn = configured[AWS_KMS_KEY_ARN_ENV]
    if not key_arn:
        raise ValueError(f"{AWS_KMS_KEY_ARN_ENV} is required when AWS KMS signing is configured")
    timeout = configured[AWS_KMS_TIMEOUT_ENV] or "5"
    try:
        parsed_timeout = float(timeout)
    except ValueError as error:
        raise ValueError(f"{AWS_KMS_TIMEOUT_ENV} must be a number") from error
    return AWSKMSConfiguration(key_arn=key_arn, timeout_seconds=parsed_timeout)
