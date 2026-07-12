#!/usr/bin/env bash
set -euo pipefail

expected_version=$(uv run python -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')
if [[ ${GITHUB_REF_TYPE:-} == "tag" && ${GITHUB_REF_NAME:-} != "v$expected_version" ]]; then
  echo "tag $GITHUB_REF_NAME does not match package version $expected_version" >&2
  exit 1
fi
rm -rf dist
uv build

wheels=(dist/*.whl)
sdists=(dist/*.tar.gz)
if [[ ${#wheels[@]} -ne 1 || ${#sdists[@]} -ne 1 ]]; then
  echo "expected one wheel and one source distribution" >&2
  exit 1
fi

workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT
uv venv "$workspace/venv" --python 3.12
uv pip install --python "$workspace/venv/bin/python" "${wheels[0]}"

"$workspace/venv/bin/python" - "${wheels[0]}" "$expected_version" <<'PY'
from importlib.metadata import version
from pathlib import Path
from zipfile import ZipFile
import sys

import aecontrol

wheel = Path(sys.argv[1])
expected_version = sys.argv[2]
assert version("aecontrol") == expected_version
assert aecontrol.AgentEvalClient
with ZipFile(wheel) as archive:
    assert "aecontrol/py.typed" in archive.namelist()
print(f"verified {wheel.name}: aecontrol {version('aecontrol')}, typed public API")
PY

"$workspace/venv/bin/aecontrol" doctor
