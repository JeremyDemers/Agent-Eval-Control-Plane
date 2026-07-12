from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from aecontrol.auth import Authenticator, hash_api_key, load_auth_config


def _write_config(path: Path, keys: str) -> Path:
    path.write_text(f"keys:\n{keys}")
    return path


def test_authenticator_disabled_mode_and_key_hashing() -> None:
    authenticator = Authenticator()

    assert authenticator.enabled is False
    assert hash_api_key("correct-horse-battery-staple") == (
        "87cbebfeebc05f7c54ac9336c4b4bbec831227a641951a4bde7edd56020f8590"
    )
    with pytest.raises(ValueError, match="must not be empty"):
        hash_api_key("")


def test_auth_config_rejects_invalid_and_duplicate_keys(tmp_path: Path) -> None:
    digest = hash_api_key("a-high-entropy-secret")
    duplicate_ids = _write_config(
        tmp_path / "duplicate-ids.yaml",
        f"  - key_id: repeated\n    secret_sha256: {digest}\n    scopes: [read]\n"
        f'  - key_id: repeated\n    secret_sha256: "{"0" * 64}"\n    scopes: [write]\n',
    )
    with pytest.raises(ValueError, match="key IDs must be unique"):
        load_auth_config(duplicate_ids)

    duplicate_digests = _write_config(
        tmp_path / "duplicate-digests.yaml",
        f"  - key_id: first\n    secret_sha256: {digest}\n    scopes: [read]\n"
        f"  - key_id: second\n    secret_sha256: {digest}\n    scopes: [write]\n",
    )
    with pytest.raises(ValueError, match="digests must be unique"):
        load_auth_config(duplicate_digests)

    invalid_scope = _write_config(
        tmp_path / "invalid-scope.yaml",
        f"  - key_id: bad\n    secret_sha256: {digest}\n    scopes: [superuser]\n",
    )
    with pytest.raises(ValidationError):
        load_auth_config(invalid_scope)
