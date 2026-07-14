from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from uuid import uuid4

import google_crc32c
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from google.api_core.exceptions import PermissionDenied
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import kms_v1

from aecontrol.aws_kms import AWS_KMS_KEY_ARN_ENV
from aecontrol.gcp_kms import (
    GCP_KMS_ENVIRONMENT,
    GCP_KMS_INTEGRITY_ATTEMPTS_ENV,
    GCP_KMS_KEY_VERSION_ENV,
    GCP_KMS_PROTECTION_LEVEL_ENV,
    GCP_KMS_TIMEOUT_ENV,
    GCPKMSConfiguration,
    GCPKMSSigner,
    GCPKMSSigningError,
    gcp_kms_configuration_from_environment,
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

KEY_VERSION = (
    "projects/agent-eval/locations/us-central1/keyRings/evidence/"
    "cryptoKeys/artifact-signing/cryptoKeyVersions/7"
)


def response(
    signature: bytes,
    *,
    name: str = KEY_VERSION,
    protection_level: kms_v1.ProtectionLevel = kms_v1.ProtectionLevel.HSM,
    verified_data_crc32c: bool = True,
    signature_crc32c: int | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        protection_level=protection_level,
        verified_data_crc32c=verified_data_crc32c,
        signature=signature,
        signature_crc32c=(
            google_crc32c.value(signature) if signature_crc32c is None else signature_crc32c
        ),
    )


class SigningClient:
    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        responses: list[SimpleNamespace] | None = None,
    ) -> None:
        self.private_key = private_key
        self.responses = list(responses or [])
        self.requests: list[tuple[dict[str, object], float]] = []

    def asymmetric_sign(self, *, request: dict[str, object], timeout: float) -> SimpleNamespace:
        self.requests.append((request, timeout))
        if self.responses:
            return self.responses.pop(0)
        return response(self.private_key.sign(request["data"]))  # type: ignore[arg-type]


def test_gcp_kms_signer_pins_raw_data_checksum_key_and_hsm() -> None:
    private_key = Ed25519PrivateKey.generate()
    client = SigningClient(private_key)
    signer = GCPKMSSigner(client, GCPKMSConfiguration(KEY_VERSION, "HSM", 4, 3), "gcp-hsm-v7")
    message = b"aecontrol:v1:run:artifact:digest"

    encoded = signer.sign(message)

    assert client.requests == [
        (
            {
                "name": KEY_VERSION,
                "data": message,
                "data_crc32c": google_crc32c.value(message),
            },
            4,
        )
    ]
    private_key.public_key().verify(base64.b64decode(encoded, validate=True), message)


def test_gcp_kms_keyring_signs_remotely_and_verifies_offline() -> None:
    private_bytes, public_bytes = generate_ed25519_keypair()
    client = SigningClient(Ed25519PrivateKey.from_private_bytes(private_bytes))
    remote = GCPKMSSigner(client, GCPKMSConfiguration(KEY_VERSION), "gcp-hsm-v7")
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


def test_integrity_failures_retry_with_a_fixed_bound_then_succeed() -> None:
    private_key = Ed25519PrivateKey.generate()
    message = b"message"
    signature = private_key.sign(message)
    client = SigningClient(
        private_key,
        [
            response(signature, verified_data_crc32c=False),
            response(signature, signature_crc32c=0),
            response(signature),
        ],
    )

    encoded = GCPKMSSigner(client, GCPKMSConfiguration(KEY_VERSION), "gcp-hsm").sign(message)

    assert len(client.requests) == 3
    private_key.public_key().verify(base64.b64decode(encoded), message)


def test_persistent_integrity_failure_is_rejected_after_configured_attempts() -> None:
    private_key = Ed25519PrivateKey.generate()
    signature = private_key.sign(b"message")
    client = SigningClient(
        private_key,
        [response(signature, verified_data_crc32c=False) for _ in range(2)],
    )
    signer = GCPKMSSigner(
        client,
        GCPKMSConfiguration(KEY_VERSION, integrity_attempts=2),
        "gcp-hsm",
    )

    with pytest.raises(GCPKMSSigningError, match="failed CRC32C"):
        signer.sign(b"message")
    assert len(client.requests) == 2


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (response(b"x" * 64, name=KEY_VERSION.replace("/7", "/8")), "unexpected key version"),
        (
            response(b"x" * 64, protection_level=kms_v1.ProtectionLevel.SOFTWARE),
            "unexpected protection level",
        ),
        (response(b"short"), "invalid Ed25519 signature"),
        (
            SimpleNamespace(
                name=KEY_VERSION,
                protection_level="not-an-enum",
                verified_data_crc32c=True,
                signature=b"x" * 64,
                signature_crc32c=google_crc32c.value(b"x" * 64),
            ),
            "unexpected protection level",
        ),
        (
            SimpleNamespace(
                name=KEY_VERSION,
                protection_level=kms_v1.ProtectionLevel.HSM,
                verified_data_crc32c=True,
                signature="not-bytes",
                signature_crc32c=0,
            ),
            "failed CRC32C",
        ),
    ],
)
def test_signer_rejects_untrusted_response_identity_and_shape(
    result: SimpleNamespace, message: str
) -> None:
    private_key = Ed25519PrivateKey.generate()
    signer = GCPKMSSigner(
        SigningClient(private_key, [result]),
        GCPKMSConfiguration(KEY_VERSION, integrity_attempts=1),
        "gcp-hsm",
    )
    with pytest.raises(GCPKMSSigningError, match=message):
        signer.sign(b"message")


def test_gcp_api_and_client_errors_are_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    class FailedClient:
        @staticmethod
        def asymmetric_sign(**_request: object) -> object:
            raise PermissionDenied("credential SECRET-GOOGLE-TOKEN cannot use hidden-key-name")

    signer = GCPKMSSigner(
        FailedClient(), GCPKMSConfiguration(KEY_VERSION, integrity_attempts=1), "gcp-hsm"
    )
    with pytest.raises(GCPKMSSigningError, match="signing request failed") as caught:
        signer.sign(b"message")
    assert "SECRET-GOOGLE-TOKEN" not in str(caught.value)
    assert "hidden-key-name" not in str(caught.value)

    def failed_client() -> object:
        raise DefaultCredentialsError("credential file /secret/account.json is missing")

    monkeypatch.setattr("aecontrol.gcp_kms.kms_v1.KeyManagementServiceClient", failed_client)
    with pytest.raises(GCPKMSSigningError, match="client configuration failed") as caught:
        GCPKMSSigner.from_configuration(GCPKMSConfiguration(KEY_VERSION), "gcp-hsm")
    assert "/secret/account.json" not in str(caught.value)


def test_signer_rejects_out_of_contract_message_size() -> None:
    signer = GCPKMSSigner(object(), GCPKMSConfiguration(KEY_VERSION), "gcp-hsm")
    with pytest.raises(GCPKMSSigningError, match="1-4096 bytes"):
        signer.sign(b"")
    with pytest.raises(GCPKMSSigningError, match="1-4096 bytes"):
        signer.sign(b"x" * 4097)


def test_configuration_loads_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in GCP_KMS_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    assert gcp_kms_configuration_from_environment() is None

    monkeypatch.setenv(GCP_KMS_KEY_VERSION_ENV, KEY_VERSION)
    loaded = gcp_kms_configuration_from_environment()
    assert loaded == GCPKMSConfiguration(KEY_VERSION)
    assert loaded.location == "us-central1"
    assert len(loaded.key_version_sha256) == 64

    monkeypatch.setenv(GCP_KMS_PROTECTION_LEVEL_ENV, "SOFTWARE")
    monkeypatch.setenv(GCP_KMS_TIMEOUT_ENV, "3.5")
    monkeypatch.setenv(GCP_KMS_INTEGRITY_ATTEMPTS_ENV, "2")
    assert gcp_kms_configuration_from_environment() == GCPKMSConfiguration(
        KEY_VERSION, "SOFTWARE", 3.5, 2
    )


def test_environment_requires_key_version_when_an_option_is_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(GCP_KMS_KEY_VERSION_ENV, "")
    monkeypatch.setenv(GCP_KMS_PROTECTION_LEVEL_ENV, "HSM")

    with pytest.raises(ValueError, match=f"{GCP_KMS_KEY_VERSION_ENV} is required"):
        gcp_kms_configuration_from_environment()


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        ({GCP_KMS_TIMEOUT_ENV: "not-a-number"}, "must be a number"),
        ({GCP_KMS_INTEGRITY_ATTEMPTS_ENV: "two"}, "must be an integer"),
    ],
)
def test_environment_rejects_invalid_numeric_values(
    monkeypatch: pytest.MonkeyPatch, environment: dict[str, str], message: str
) -> None:
    monkeypatch.setenv(GCP_KMS_KEY_VERSION_ENV, KEY_VERSION)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=message):
        gcp_kms_configuration_from_environment()


@pytest.mark.parametrize(
    ("configuration", "message"),
    [
        (("cryptoKeys/key/cryptoKeyVersions/1", "HSM", 5, 3), "full immutable"),
        ((KEY_VERSION.replace("/7", "/0"), "HSM", 5, 3), "full immutable"),
        ((KEY_VERSION, "UNKNOWN", 5, 3), "must be one of"),
        ((KEY_VERSION, "HSM", 0, 3), "between 0.1 and 30"),
        ((KEY_VERSION, "HSM", 31, 3), "between 0.1 and 30"),
        ((KEY_VERSION, "HSM", 5, 0), "between 1 and 5"),
        ((KEY_VERSION, "HSM", 5, 6), "between 1 and 5"),
    ],
)
def test_configuration_rejects_unpinned_or_unsafe_values(
    configuration: tuple[str, str, float, int], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        GCPKMSConfiguration(*configuration)


def test_keyring_builds_gcp_signer_and_rejects_conflicting_remote_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_bytes, public_bytes = generate_ed25519_keypair()
    client = SigningClient(Ed25519PrivateKey.from_private_bytes(private_bytes))
    monkeypatch.setattr("aecontrol.gcp_kms.kms_v1.KeyManagementServiceClient", lambda: client)
    monkeypatch.setenv(SIGNING_KEY_ID_ENV, "gcp-hsm-v7")
    monkeypatch.setenv(SIGNING_ALGORITHM_ENV, ED25519)
    monkeypatch.setenv(
        ED25519_PUBLIC_KEYS_ENV,
        json.dumps({"gcp-hsm-v7": base64.b64encode(public_bytes).decode()}),
    )
    monkeypatch.setenv(GCP_KMS_KEY_VERSION_ENV, KEY_VERSION)

    keyring = ArtifactKeyring.from_environment()
    assert keyring is not None
    signature = keyring.sign("run", uuid4(), "a" * 64)
    assert len(base64.b64decode(signature)) == 64

    monkeypatch.setenv(
        AWS_KMS_KEY_ARN_ENV,
        "arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-1234567890ab",
    )
    with pytest.raises(ValueError, match="mutually exclusive"):
        ArtifactKeyring.from_environment()
    monkeypatch.delenv(AWS_KMS_KEY_ARN_ENV)
    monkeypatch.setenv(VAULT_ADDR_ENV, "https://vault.example")
    monkeypatch.setenv(VAULT_TOKEN_ENV, "workload-token")
    monkeypatch.setenv(VAULT_KEY_ENV, "artifact-evidence")
    monkeypatch.setenv(VAULT_KEY_VERSION_ENV, "1")
    with pytest.raises(ValueError, match="mutually exclusive"):
        ArtifactKeyring.from_environment()


def test_gcp_kms_requires_active_ed25519_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(GCP_KMS_KEY_VERSION_ENV, KEY_VERSION)
    with pytest.raises(ValueError, match="active Ed25519"):
        ArtifactKeyring.from_environment()
