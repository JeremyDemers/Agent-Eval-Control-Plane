from __future__ import annotations

import base64
import io
import json
from urllib.error import HTTPError, URLError
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aecontrol.integrity import (
    ED25519,
    ED25519_PUBLIC_KEYS_ENV,
    SIGNING_ALGORITHM_ENV,
    SIGNING_KEY_ID_ENV,
    ArtifactKeyring,
    generate_ed25519_keypair,
)
from aecontrol.vault import (
    VAULT_ADDR_ENV,
    VAULT_ENVIRONMENT,
    VAULT_KEY_ENV,
    VAULT_KEY_VERSION_ENV,
    VAULT_NAMESPACE_ENV,
    VAULT_TOKEN_ENV,
    VAULT_TOKEN_FILE_ENV,
    VaultTransitConfiguration,
    VaultTransitError,
    VaultTransitSigner,
    vault_configuration_from_environment,
)


class Response:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


def configuration(**overrides: object) -> VaultTransitConfiguration:
    values: dict[str, object] = {
        "address": "https://vault.example",
        "token": "hvs.test-token",
        "mount": "team/transit",
        "key_name": "agent-evidence",
        "key_version": 7,
        "namespace": "nvidia/platform",
        "timeout_seconds": 3,
    }
    values.update(overrides)
    return VaultTransitConfiguration(**values)  # type: ignore[arg-type]


def vault_response(signature: bytes, version: int = 7) -> bytes:
    encoded = base64.b64encode(signature).decode()
    return json.dumps({"data": {"signature": f"vault:v{version}:{encoded}"}}).encode()


def test_vault_transit_signer_sends_pinned_ed25519_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def open_request(request, timeout):  # type: ignore[no-untyped-def]
        observed.update(request=request, timeout=timeout)
        return Response(vault_response(b"s" * 64))

    monkeypatch.setattr("aecontrol.vault.urlopen", open_request)
    signer = VaultTransitSigner(configuration(), "vault-evidence-v7")

    signature = signer.sign(b"domain-separated-message")

    request = observed["request"]
    assert request.full_url == "https://vault.example/v1/team/transit/sign/agent-evidence"
    assert request.method == "POST"
    assert request.get_header("X-vault-token") == "hvs.test-token"
    assert request.get_header("X-vault-namespace") == "nvidia/platform"
    assert json.loads(request.data) == {
        "input": base64.b64encode(b"domain-separated-message").decode(),
        "key_version": 7,
    }
    assert observed["timeout"] == 3
    assert base64.b64decode(signature, validate=True) == b"s" * 64


def test_remote_keyring_signatures_verify_offline_without_vault_private_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_bytes, public_bytes = generate_ed25519_keypair()
    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)

    def open_request(request, timeout):  # type: ignore[no-untyped-def]
        assert timeout == 5
        message = base64.b64decode(json.loads(request.data)["input"], validate=True)
        return Response(vault_response(private_key.sign(message)))

    monkeypatch.setattr("aecontrol.vault.urlopen", open_request)
    monkeypatch.setenv(SIGNING_KEY_ID_ENV, "vault-evidence-v7")
    monkeypatch.setenv(SIGNING_ALGORITHM_ENV, ED25519)
    monkeypatch.setenv(
        ED25519_PUBLIC_KEYS_ENV,
        json.dumps({"vault-evidence-v7": base64.b64encode(public_bytes).decode()}),
    )
    monkeypatch.setenv(VAULT_ADDR_ENV, "https://vault.example")
    monkeypatch.setenv(VAULT_TOKEN_ENV, "hvs.workload-token")
    monkeypatch.setenv(VAULT_KEY_ENV, "agent-evidence")
    monkeypatch.setenv(VAULT_KEY_VERSION_ENV, "7")
    signer = ArtifactKeyring.from_environment()
    assert signer is not None

    artifact_id = uuid4()
    signature = signer.sign("run", artifact_id, "a" * 64)
    verifier = ArtifactKeyring(ed25519_public_keys={"vault-evidence-v7": public_bytes})

    assert verifier.verify(ED25519, "vault-evidence-v7", "run", artifact_id, "a" * 64, signature)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"not-json", "invalid signing response"),
        (b"\xff", "invalid signing response"),
        (b"{}", "invalid signing response"),
        (vault_response(b"s" * 64, version=8), "unexpected key version"),
        (json.dumps({"data": {"signature": "vault:v7:%%%"}}).encode(), "invalid Ed25519"),
        (vault_response(b"short"), "invalid Ed25519"),
        (b"x" * (1024 * 1024 + 1), "exceeded 1 MiB"),
    ],
)
def test_vault_transit_signer_rejects_untrusted_responses(
    monkeypatch: pytest.MonkeyPatch, body: bytes, message: str
) -> None:
    monkeypatch.setattr("aecontrol.vault.urlopen", lambda *_args, **_kwargs: Response(body))

    with pytest.raises(VaultTransitError, match=message):
        VaultTransitSigner(configuration(), "vault-evidence-v7").sign(b"message")


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (
            HTTPError("https://vault.example", 403, "denied", {}, io.BytesIO(b"secret")),
            "HTTP 403",
        ),
        (URLError("connection includes sensitive details"), "signing request failed"),
        (TimeoutError("token=hvs.secret"), "signing request failed"),
    ],
)
def test_vault_transit_errors_are_sanitized(
    monkeypatch: pytest.MonkeyPatch, error: Exception, message: str
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr("aecontrol.vault.urlopen", fail)

    with pytest.raises(VaultTransitError, match=message) as caught:
        VaultTransitSigner(configuration(), "vault-evidence-v7").sign(b"message")
    assert "sensitive" not in str(caught.value)
    assert "hvs.secret" not in str(caught.value)


def test_vault_configuration_loads_bounded_token_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:  # type: ignore[no-untyped-def]
    token_file = tmp_path / "token"
    token_file.write_text("hvs.from-agent\n")
    for name in VAULT_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(VAULT_ADDR_ENV, "http://127.0.0.1:8200")
    monkeypatch.setenv(VAULT_TOKEN_FILE_ENV, str(token_file))
    monkeypatch.setenv(VAULT_KEY_ENV, "agent-evidence")
    monkeypatch.setenv(VAULT_KEY_VERSION_ENV, "3")
    monkeypatch.setenv(VAULT_NAMESPACE_ENV, "tenant-a")

    loaded = vault_configuration_from_environment()

    assert loaded is not None
    assert loaded.token == "hvs.from-agent"
    assert loaded.endpoint_host == "127.0.0.1"
    assert loaded.sign_url == "http://127.0.0.1:8200/v1/transit/sign/agent-evidence"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"address": "http://vault.example"}, "must use HTTPS"),
        ({"address": "https://user:password@vault.example"}, "origin-only"),
        ({"address": "file:///tmp/vault"}, "origin-only"),
        ({"token": "token with spaces"}, "printable ASCII"),
        ({"mount": "../transit"}, "normalized Vault path"),
        ({"key_name": "key/name"}, "normalized Vault key name"),
        ({"key_version": 0}, "positive integer"),
        ({"namespace": "bad\nnamespace"}, "bounded value"),
        ({"timeout_seconds": 31}, "between 0.1 and 30"),
    ],
)
def test_vault_configuration_rejects_unsafe_values(
    overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        configuration(**overrides)


def test_vault_environment_requires_exactly_one_token_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in VAULT_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(VAULT_ADDR_ENV, "https://vault.example")
    monkeypatch.setenv(VAULT_KEY_ENV, "agent-evidence")
    monkeypatch.setenv(VAULT_KEY_VERSION_ENV, "1")

    with pytest.raises(ValueError, match="exactly one"):
        vault_configuration_from_environment()

    monkeypatch.setenv(VAULT_TOKEN_ENV, "direct")
    monkeypatch.setenv(VAULT_TOKEN_FILE_ENV, "/var/run/secrets/vault-token")
    with pytest.raises(ValueError, match="exactly one"):
        vault_configuration_from_environment()


def test_keyring_rejects_vault_without_active_ed25519_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in VAULT_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(VAULT_ADDR_ENV, "https://vault.example")
    monkeypatch.setenv(VAULT_TOKEN_ENV, "workload-token")
    monkeypatch.setenv(VAULT_KEY_ENV, "agent-evidence")
    monkeypatch.setenv(VAULT_KEY_VERSION_ENV, "1")

    with pytest.raises(ValueError, match="active Ed25519"):
        ArtifactKeyring.from_environment()


def test_vault_token_file_is_size_and_encoding_bounded(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:  # type: ignore[no-untyped-def]
    for name in VAULT_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(VAULT_ADDR_ENV, "https://vault.example")
    monkeypatch.setenv(VAULT_KEY_ENV, "agent-evidence")
    monkeypatch.setenv(VAULT_KEY_VERSION_ENV, "1")
    token_file = tmp_path / "token"
    monkeypatch.setenv(VAULT_TOKEN_FILE_ENV, str(token_file))

    token_file.write_bytes(b"x" * (16 * 1024 + 1))
    with pytest.raises(ValueError, match="no larger than 16 KiB"):
        vault_configuration_from_environment()

    token_file.write_bytes(b"\xff")
    with pytest.raises(ValueError, match="printable ASCII"):
        vault_configuration_from_environment()
