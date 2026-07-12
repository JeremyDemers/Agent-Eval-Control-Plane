# Releases

AgentEval produces a Python wheel and source distribution from the same locked source tree tested in
CI. The release process does not publish to PyPI; artifacts are attached to versioned GitHub Releases.

## Local verification

```bash
make package
uvx twine check dist/*
```

The package smoke test:

1. Builds the sdist and builds the wheel from that sdist.
2. Requires exactly one artifact of each type.
3. Creates a clean Python 3.12 virtual environment.
4. Installs the wheel and its declared runtime dependencies.
5. Confirms installed metadata matches `pyproject.toml`.
6. Confirms the wheel contains `aecontrol/py.typed`.
7. Imports the public SDK and runs the installed `aecontrol doctor` command.

## Tagged releases

Pushing `v0.15.0` runs `.github/workflows/release.yml`. The workflow rejects a tag that does not
match the package version, repeats the clean-install smoke test, creates GitHub artifact-provenance
attestations for both distributions, and publishes a GitHub Release with generated notes.

Consumers can verify a downloaded artifact against the repository and GitHub Actions identity:

```bash
gh attestation verify aecontrol-0.15.0-py3-none-any.whl \
  --repo JeremyDemers/Agent-Eval-Control-Plane
```

The attestation proves which repository workflow produced an artifact. It does not make the package
safe by itself; consumers should still review source, dependency policy, and the release tag.
