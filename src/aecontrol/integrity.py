from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any
from uuid import UUID


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


class ArtifactIntegrityError(RuntimeError):
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


def verify_digest(expected: str, payload: Any) -> str:
    actual = artifact_digest(payload)
    if not hmac.compare_digest(expected, actual):
        raise ValueError(actual)
    return actual
