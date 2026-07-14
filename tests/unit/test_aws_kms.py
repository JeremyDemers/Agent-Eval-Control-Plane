from __future__ import annotations

import base64
import json
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aecontrol.aws_kms import (
    AWS_KMS_ENVIRONMENT,
    AWS_KMS_KEY_ARN_ENV,
    AWS_KMS_SIGNING_ALGORITHM,
    AWS_KMS_TIMEOUT_ENV,
    AWSKMSConfiguration,
    AWSKMSSigner,
    AWSKMSSigningError,
    aws_kms_configuration_from_environment,
)
from aecontrol.integrity import (
    ED25519,
    ED25519_PUBLIC_KEYS_ENV,
    SIGNING_ALGORITHM_ENV,
    SIGNING_KEY_ID_ENV,
    ArtifactKeyring,
    generate_ed25519_keypair,
)
from aecontrol.vault import VAULT_ADDR_ENV, VAULT_KEY_ENV, VAULT_KEY_VERSION_ENV, VAULT_TOKEN_ENV

KEY_ARN = "arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-1234567890ab"


class SigningClient:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self.private_key = private_key
        self.request: dict[str, object] | None = None

    def sign(self, **request: object) -> dict[str, object]:
        self.request = request
        return {
            "KeyId": KEY_ARN,
            "SigningAlgorithm": AWS_KMS_SIGNING_ALGORITHM,
            "Signature": self.private_key.sign(request["Message"]),  # type: ignore[arg-type]
        }


def test_aws_kms_signer_pins_key_algorithm_and_raw_message() -> None:
    private_bytes, public_bytes = generate_ed25519_keypair()
    client = SigningClient(Ed25519PrivateKey.from_private_bytes(private_bytes))
    signer = AWSKMSSigner(client, AWSKMSConfiguration(KEY_ARN, 3), "kms-evidence-2026-07")
    message = b"aecontrol:v1:run:artifact:digest"

    signature = signer.sign(message)

    assert client.request == {
        "KeyId": KEY_ARN,
        "Message": message,
        "MessageType": "RAW",
        "SigningAlgorithm": "ED25519_SHA_512",
    }
    Ed25519PrivateKey.from_private_bytes(private_bytes).public_key().verify(
        base64.b64decode(signature, validate=True), message
    )
    assert len(public_bytes) == 32


def test_aws_kms_keyring_signs_remotely_and_verifies_offline() -> None:
    private_bytes, public_bytes = generate_ed25519_keypair()
    client = SigningClient(Ed25519PrivateKey.from_private_bytes(private_bytes))
    remote = AWSKMSSigner(client, AWSKMSConfiguration(KEY_ARN), "kms-evidence-2026-07")
    signer = ArtifactKeyring(
        active_key_id=remote.key_id,
        active_algorithm=ED25519,
        ed25519_public_keys={remote.key_id: public_bytes},
        remote_signer=remote,
    )
    verifier = ArtifactKeyring(ed25519_public_keys={remote.key_id: public_bytes})
    artifact_id = uuid4()

    signature = signer.sign("checkpoint", artifact_id, "a" * 64)

    assert verifier.verify(ED25519, remote.key_id, "checkpoint", artifact_id, "a" * 64, signature)


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (None, "invalid signing response"),
        ({}, "unexpected signing key"),
        (
            {
                "KeyId": "arn:aws:kms:us-east-2:123456789012:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            },
            "unexpected signing key",
        ),
        ({"KeyId": KEY_ARN, "SigningAlgorithm": "ECDSA_SHA_256"}, "unexpected signing algorithm"),
        (
            {"KeyId": KEY_ARN, "SigningAlgorithm": AWS_KMS_SIGNING_ALGORITHM},
            "invalid Ed25519 signature",
        ),
        (
            {
                "KeyId": KEY_ARN,
                "SigningAlgorithm": AWS_KMS_SIGNING_ALGORITHM,
                "Signature": b"short",
            },
            "invalid Ed25519 signature",
        ),
    ],
)
def test_aws_kms_signer_rejects_untrusted_responses(response: object, message: str) -> None:
    class Client:
        @staticmethod
        def sign(**_request: object) -> object:
            return response

    with pytest.raises(AWSKMSSigningError, match=message):
        AWSKMSSigner(Client(), AWSKMSConfiguration(KEY_ARN), "kms-evidence").sign(b"message")


def test_aws_kms_errors_are_sanitized() -> None:
    class Client:
        @staticmethod
        def sign(**_request: object) -> object:
            raise ClientError(
                {
                    "Error": {
                        "Code": "AccessDeniedException",
                        "Message": "credential AKIA-SENSITIVE was denied",
                    }
                },
                "Sign",
            )

    with pytest.raises(AWSKMSSigningError, match="signing request failed") as caught:
        AWSKMSSigner(Client(), AWSKMSConfiguration(KEY_ARN), "kms-evidence").sign(b"message")
    assert "AKIA-SENSITIVE" not in str(caught.value)
    assert "AccessDenied" not in str(caught.value)


def test_aws_kms_signer_rejects_out_of_contract_message_size() -> None:
    signer = AWSKMSSigner(object(), AWSKMSConfiguration(KEY_ARN), "kms-evidence")
    with pytest.raises(AWSKMSSigningError, match="1-4096 bytes"):
        signer.sign(b"")
    with pytest.raises(AWSKMSSigningError, match="1-4096 bytes"):
        signer.sign(b"x" * 4097)


def test_aws_kms_environment_builds_sdk_client(monkeypatch: pytest.MonkeyPatch) -> None:
    _, public_bytes = generate_ed25519_keypair()
    observed: dict[str, object] = {}

    def client(service: str, **options: object) -> object:
        observed.update(service=service, **options)
        return object()

    monkeypatch.setattr("boto3.client", client)
    monkeypatch.setenv(SIGNING_KEY_ID_ENV, "kms-evidence")
    monkeypatch.setenv(SIGNING_ALGORITHM_ENV, ED25519)
    monkeypatch.setenv(
        ED25519_PUBLIC_KEYS_ENV,
        json.dumps({"kms-evidence": base64.b64encode(public_bytes).decode()}),
    )
    monkeypatch.setenv(AWS_KMS_KEY_ARN_ENV, KEY_ARN)
    monkeypatch.setenv(AWS_KMS_TIMEOUT_ENV, "3")

    keyring = ArtifactKeyring.from_environment()

    assert keyring is not None
    assert keyring.active_algorithm == ED25519
    assert observed["service"] == "kms"
    assert observed["region_name"] == "us-east-2"
    config = observed["config"]
    assert config.connect_timeout == 3  # type: ignore[attr-defined]
    assert config.read_timeout == 3  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("key_arn", "timeout", "message"),
    [
        ("alias/agent-evidence", 5, "full asymmetric KMS key ARN"),
        (
            "arn:aws:kms:us-east-2:123456789012:alias/agent-evidence",
            5,
            "not an alias",
        ),
        (KEY_ARN, 0, "between 0.1 and 30"),
        (KEY_ARN, 31, "between 0.1 and 30"),
    ],
)
def test_aws_kms_configuration_rejects_unpinned_or_unsafe_values(
    key_arn: str, timeout: float, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        AWSKMSConfiguration(key_arn, timeout)


def test_aws_kms_configuration_loads_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in AWS_KMS_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    assert aws_kms_configuration_from_environment() is None

    monkeypatch.setenv(AWS_KMS_KEY_ARN_ENV, KEY_ARN)
    loaded = aws_kms_configuration_from_environment()
    assert loaded == AWSKMSConfiguration(KEY_ARN)
    assert loaded.region == "us-east-2"
    assert len(loaded.key_arn_sha256) == 64

    monkeypatch.setenv(AWS_KMS_TIMEOUT_ENV, "not-a-number")
    with pytest.raises(ValueError, match="must be a number"):
        aws_kms_configuration_from_environment()

    monkeypatch.delenv(AWS_KMS_KEY_ARN_ENV)
    monkeypatch.setenv(AWS_KMS_TIMEOUT_ENV, "5")
    with pytest.raises(ValueError, match="is required"):
        aws_kms_configuration_from_environment()


def test_keyring_rejects_kms_without_ed25519_or_alongside_vault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(AWS_KMS_KEY_ARN_ENV, KEY_ARN)
    with pytest.raises(ValueError, match="active Ed25519"):
        ArtifactKeyring.from_environment()

    _, public_bytes = generate_ed25519_keypair()
    monkeypatch.setenv(SIGNING_KEY_ID_ENV, "remote-evidence")
    monkeypatch.setenv(SIGNING_ALGORITHM_ENV, ED25519)
    monkeypatch.setenv(
        ED25519_PUBLIC_KEYS_ENV,
        json.dumps({"remote-evidence": base64.b64encode(public_bytes).decode()}),
    )
    monkeypatch.setenv(VAULT_ADDR_ENV, "https://vault.example")
    monkeypatch.setenv(VAULT_TOKEN_ENV, "workload-token")
    monkeypatch.setenv(VAULT_KEY_ENV, "agent-evidence")
    monkeypatch.setenv(VAULT_KEY_VERSION_ENV, "1")
    with pytest.raises(ValueError, match="mutually exclusive"):
        ArtifactKeyring.from_environment()
