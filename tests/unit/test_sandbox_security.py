from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from aecontrol.models import DatasetCase
from aecontrol.sandbox import (
    CodingSandbox,
    PodmanSandboxConfiguration,
    PodmanTestExecutor,
    ProcessTestExecutor,
    SandboxPolicy,
    podman_sandbox_configuration_from_environment,
    validate_source,
)

DIGEST_IMAGE = "docker.io/library/python@sha256:" + "a" * 64


def make_case() -> DatasetCase:
    return DatasetCase(
        case_id="SEC-SANDBOX",
        title="sandbox",
        slice="general_python",
        bug_kind="divide",
    )


def test_source_validation_rejects_dangerous_or_invalid_code() -> None:
    policy = SandboxPolicy(max_source_bytes=32)

    assert validate_source("import socket\n", policy) == "source rejected: denied import socket"
    assert validate_source("open('/etc/passwd')\n", policy) == "source rejected: denied call open"
    assert validate_source("def broken(:\n", policy).startswith("source rejected: syntax error")
    assert validate_source("x" * 33, policy) == "source rejected: exceeds 32 byte limit"


def test_process_executor_stops_infinite_candidate() -> None:
    sandbox = CodingSandbox(
        executor=ProcessTestExecutor(),
        policy=SandboxPolicy(timeout_seconds=0.1),
    )

    result = sandbox.run(make_case(), "def solve(a, b):\n    while True:\n        pass\n")

    assert not result.public_passed
    assert "sandbox timeout" in result.public_test_output
    assert result.backend == "process"


def test_rejected_source_never_reaches_executor() -> None:
    executor = Mock(name="executor", spec=ProcessTestExecutor)
    executor.name = "mock"
    sandbox = CodingSandbox(executor=executor)

    result = sandbox.run(make_case(), "import subprocess\n")

    assert not result.public_passed
    assert "denied import subprocess" in result.public_test_output
    executor.run_test.assert_not_called()


def test_podman_executor_applies_isolation_flags(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    test_path = tmp_path / "_aecontrol_test.py"
    test_path.write_text("assert True\n")
    monkeypatch.setattr("aecontrol.sandbox.shutil.which", Mock(return_value="/usr/bin/podman"))
    completed = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
    run = Mock(return_value=completed)
    monkeypatch.setattr("aecontrol.sandbox.subprocess.run", run)

    passed, output = PodmanTestExecutor().run_test(tmp_path, test_path, SandboxPolicy())

    assert passed
    assert output == "ok"
    command = run.call_args.args[0]
    assert "--network=none" in command
    assert "--pull=never" in command
    assert "--name" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--user=65534:65534" in command


def test_podman_configuration_enforces_digest_and_policy_inputs(tmp_path: Path) -> None:
    seccomp = tmp_path / "seccomp.json"
    seccomp.write_text("{}")
    configuration = PodmanSandboxConfiguration(
        image=DIGEST_IMAGE,
        require_digest=True,
        seccomp_profile=seccomp,
        apparmor_profile="aecontrol-sandbox",
    )

    assert configuration.digest_pinned is True
    assert configuration.seccomp_profile == seccomp.resolve()
    with pytest.raises(ValueError, match="pinned by SHA-256"):
        PodmanSandboxConfiguration(image="python:3.12-slim", require_digest=True)
    with pytest.raises(ValueError, match="invalid SHA-256"):
        PodmanSandboxConfiguration(image="python@sha256:1234")
    with pytest.raises(ValueError, match="readable regular file"):
        PodmanSandboxConfiguration(seccomp_profile=tmp_path / "missing.json")
    with pytest.raises(ValueError, match="cannot disable confinement"):
        PodmanSandboxConfiguration(apparmor_profile="unconfined")


def test_podman_configuration_reads_strict_environment(tmp_path: Path) -> None:
    seccomp = tmp_path / "seccomp.json"
    seccomp.write_text("{}")
    configuration = podman_sandbox_configuration_from_environment(
        {
            "AECONTROL_SANDBOX_IMAGE": DIGEST_IMAGE,
            "AECONTROL_SANDBOX_REQUIRE_DIGEST": "true",
            "AECONTROL_SANDBOX_SECCOMP_PROFILE": str(seccomp),
            "AECONTROL_SANDBOX_APPARMOR_PROFILE": "aecontrol-sandbox",
        }
    )

    assert configuration.require_digest is True
    assert configuration.seccomp_profile == seccomp.resolve()
    assert configuration.apparmor_profile == "aecontrol-sandbox"
    with pytest.raises(ValueError, match="must be a boolean"):
        podman_sandbox_configuration_from_environment(
            {"AECONTROL_SANDBOX_REQUIRE_DIGEST": "sometimes"}
        )


def test_podman_executor_forwards_custom_kernel_policies(
    monkeypatch,
    tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    test_path = tmp_path / "_aecontrol_test.py"
    test_path.write_text("assert True\n")
    seccomp = tmp_path / "seccomp.json"
    seccomp.write_text("{}")
    monkeypatch.setattr("aecontrol.sandbox.shutil.which", Mock(return_value="/usr/bin/podman"))
    run = Mock(return_value=subprocess.CompletedProcess([], 0, stdout="ok", stderr=""))
    monkeypatch.setattr("aecontrol.sandbox.subprocess.run", run)

    executor = PodmanTestExecutor(
        DIGEST_IMAGE,
        require_digest=True,
        seccomp_profile=seccomp,
        apparmor_profile="aecontrol-sandbox",
    )
    executor.run_test(tmp_path, test_path, SandboxPolicy())

    command = run.call_args.args[0]
    assert f"--security-opt=seccomp={seccomp.resolve()}" in command
    assert "--security-opt=apparmor=aecontrol-sandbox" in command
    assert DIGEST_IMAGE in command


def test_podman_executor_force_removes_timed_out_container(
    monkeypatch,
    tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    test_path = tmp_path / "_aecontrol_test.py"
    test_path.write_text("assert True\n")
    monkeypatch.setattr("aecontrol.sandbox.shutil.which", Mock(return_value="/usr/bin/podman"))
    run = Mock(
        side_effect=[
            subprocess.TimeoutExpired("podman", 5),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        ]
    )
    monkeypatch.setattr("aecontrol.sandbox.subprocess.run", run)

    passed, output = PodmanTestExecutor().run_test(tmp_path, test_path, SandboxPolicy())

    assert not passed
    assert "container sandbox timeout" in output
    cleanup = run.call_args_list[1].args[0]
    assert cleanup[:3] == ["/usr/bin/podman", "rm", "--force"]
