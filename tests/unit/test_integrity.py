from __future__ import annotations

import pytest

from aecontrol.integrity import artifact_digest, verify_digest


def test_artifact_digest_is_canonical_and_verifiable() -> None:
    first = {"unicode": "caf\u00e9", "nested": {"b": 2, "a": 1}}
    reordered = {"nested": {"a": 1, "b": 2}, "unicode": "caf\u00e9"}

    digest = artifact_digest(first)

    assert digest == artifact_digest(reordered)
    assert artifact_digest({"zero": -0.0}) == artifact_digest({"zero": 0.0})
    assert len(digest) == 64
    assert verify_digest(digest, reordered) == digest
    with pytest.raises(ValueError):
        verify_digest("0" * 64, first)
    with pytest.raises(ValueError):
        artifact_digest({"invalid": float("nan")})
