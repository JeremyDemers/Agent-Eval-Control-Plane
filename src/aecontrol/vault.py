from __future__ import annotations

import json
import os
import re
from base64 import b64decode, b64encode
from binascii import Error as Base64Error
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from aecontrol.integrity import ArtifactSigningError

VAULT_ADDR_ENV = "AECONTROL_ARTIFACT_VAULT_ADDR"
VAULT_TOKEN_ENV = "AECONTROL_ARTIFACT_VAULT_TOKEN"
VAULT_TOKEN_FILE_ENV = "AECONTROL_ARTIFACT_VAULT_TOKEN_FILE"
VAULT_NAMESPACE_ENV = "AECONTROL_ARTIFACT_VAULT_NAMESPACE"
VAULT_MOUNT_ENV = "AECONTROL_ARTIFACT_VAULT_MOUNT"
VAULT_KEY_ENV = "AECONTROL_ARTIFACT_VAULT_KEY"
VAULT_KEY_VERSION_ENV = "AECONTROL_ARTIFACT_VAULT_KEY_VERSION"
VAULT_TIMEOUT_ENV = "AECONTROL_ARTIFACT_VAULT_TIMEOUT_SECONDS"
VAULT_ENVIRONMENT = (
    VAULT_ADDR_ENV,
    VAULT_TOKEN_ENV,
    VAULT_TOKEN_FILE_ENV,
    VAULT_NAMESPACE_ENV,
    VAULT_MOUNT_ENV,
    VAULT_KEY_ENV,
    VAULT_KEY_VERSION_ENV,
    VAULT_TIMEOUT_ENV,
)
_PATH_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_TOKEN_BYTES = 16 * 1024
_MAX_RESPONSE_BYTES = 1024 * 1024


class VaultTransitError(ArtifactSigningError):
    """Vault Transit could not produce a trusted signature."""


@dataclass(frozen=True)
class VaultTransitConfiguration:
    address: str
    token: str
    mount: str
    key_name: str
    key_version: int
    namespace: str | None = None
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        parsed = urlparse(self.address)
        try:
            _ = parsed.port
        except ValueError as error:
            raise ValueError(f"{VAULT_ADDR_ENV} must be an origin-only HTTP(S) URL") from error
        loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError(f"{VAULT_ADDR_ENV} must be an origin-only HTTP(S) URL")
        if parsed.scheme != "https" and not loopback:
            raise ValueError(f"{VAULT_ADDR_ENV} must use HTTPS except for loopback development")
        if (
            not self.token
            or len(self.token.encode()) > _MAX_TOKEN_BYTES
            or any(not 33 <= ord(character) <= 126 for character in self.token)
        ):
            raise ValueError("Vault token must contain 1-16384 printable ASCII characters")
        if not _PATH_PATTERN.fullmatch(self.mount) or any(
            segment in {"", ".", ".."} for segment in self.mount.split("/")
        ):
            raise ValueError(f"{VAULT_MOUNT_ENV} must be a normalized Vault path")
        if not _KEY_PATTERN.fullmatch(self.key_name):
            raise ValueError(f"{VAULT_KEY_ENV} must be a normalized Vault key name")
        if self.key_version < 1:
            raise ValueError(f"{VAULT_KEY_VERSION_ENV} must be a positive integer")
        if self.namespace is not None and (
            not self.namespace
            or len(self.namespace) > 256
            or any(ord(character) < 32 or ord(character) == 127 for character in self.namespace)
        ):
            raise ValueError(f"{VAULT_NAMESPACE_ENV} must be a non-empty bounded value")
        if not 0.1 <= self.timeout_seconds <= 30:
            raise ValueError(f"{VAULT_TIMEOUT_ENV} must be between 0.1 and 30 seconds")

    @property
    def endpoint_host(self) -> str:
        return cast(str, urlparse(self.address).hostname)

    @property
    def sign_url(self) -> str:
        path = "/".join(quote(segment, safe="") for segment in self.mount.split("/"))
        key = quote(self.key_name, safe="")
        return f"{self.address.rstrip('/')}/v1/{path}/sign/{key}"


class VaultTransitSigner:
    algorithm = "ed25519"

    def __init__(self, configuration: VaultTransitConfiguration, key_id: str) -> None:
        self.configuration = configuration
        self.key_id = key_id

    def sign(self, message: bytes) -> str:
        body = json.dumps(
            {
                "input": b64encode(message).decode(),
                "key_version": self.configuration.key_version,
            },
            separators=(",", ":"),
        ).encode()
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Vault-Token": self.configuration.token,
        }
        if self.configuration.namespace is not None:
            headers["X-Vault-Namespace"] = self.configuration.namespace
        request = Request(  # noqa: S310 - configuration accepts only validated HTTP(S) origins
            self.configuration.sign_url,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.configuration.timeout_seconds) as response:  # noqa: S310
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            raise VaultTransitError(
                f"Vault Transit signing failed with HTTP {error.code}"
            ) from error
        except (URLError, TimeoutError, OSError) as error:
            raise VaultTransitError("Vault Transit signing request failed") from error
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise VaultTransitError("Vault Transit signing response exceeded 1 MiB")
        try:
            payload = json.loads(raw)
            signature = payload["data"]["signature"]
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError) as error:
            raise VaultTransitError("Vault Transit returned an invalid signing response") from error
        if not isinstance(signature, str):
            raise VaultTransitError("Vault Transit returned an invalid signing response")
        prefix, separator, encoded = signature.rpartition(":")
        expected_prefix = f"vault:v{self.configuration.key_version}"
        if separator != ":" or prefix != expected_prefix:
            raise VaultTransitError("Vault Transit returned an unexpected key version")
        try:
            decoded = b64decode(encoded, validate=True)
        except (Base64Error, ValueError) as error:
            raise VaultTransitError(
                "Vault Transit returned an invalid Ed25519 signature"
            ) from error
        if len(decoded) != 64:
            raise VaultTransitError("Vault Transit returned an invalid Ed25519 signature")
        return b64encode(decoded).decode()


def vault_configuration_from_environment() -> VaultTransitConfiguration | None:
    configured = {name: os.getenv(name) for name in VAULT_ENVIRONMENT}
    if not any(value is not None for value in configured.values()):
        return None
    address = configured[VAULT_ADDR_ENV]
    key_name = configured[VAULT_KEY_ENV]
    key_version = configured[VAULT_KEY_VERSION_ENV]
    if not address or not key_name or not key_version:
        raise ValueError(
            f"{VAULT_ADDR_ENV}, {VAULT_KEY_ENV}, and {VAULT_KEY_VERSION_ENV} must be set together"
        )
    token = _vault_token(configured[VAULT_TOKEN_ENV], configured[VAULT_TOKEN_FILE_ENV])
    try:
        parsed_version = int(key_version)
    except ValueError as error:
        raise ValueError(f"{VAULT_KEY_VERSION_ENV} must be a positive integer") from error
    timeout = configured[VAULT_TIMEOUT_ENV] or "5"
    try:
        parsed_timeout = float(timeout)
    except ValueError as error:
        raise ValueError(f"{VAULT_TIMEOUT_ENV} must be a number") from error
    return VaultTransitConfiguration(
        address=address,
        token=token,
        mount=configured[VAULT_MOUNT_ENV] or "transit",
        key_name=key_name,
        key_version=parsed_version,
        namespace=configured[VAULT_NAMESPACE_ENV],
        timeout_seconds=parsed_timeout,
    )


def _vault_token(token: str | None, token_file: str | None) -> str:
    if (token is None) == (token_file is None):
        raise ValueError(f"exactly one of {VAULT_TOKEN_ENV} or {VAULT_TOKEN_FILE_ENV} must be set")
    if token is not None:
        return token
    path = Path(cast(str, token_file))
    try:
        if not path.is_file():
            raise ValueError("Vault token file must be a regular file no larger than 16 KiB")
        with path.open("rb") as stream:
            raw = stream.read(_MAX_TOKEN_BYTES + 1)
    except OSError as error:
        raise ValueError("Vault token file could not be read") from error
    if len(raw) > _MAX_TOKEN_BYTES:
        raise ValueError("Vault token file must be a regular file no larger than 16 KiB")
    try:
        return raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ValueError("Vault token file must contain a printable ASCII token") from error
