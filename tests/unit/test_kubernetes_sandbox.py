from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from aecontrol.kubernetes_sandbox import (
    KUBERNETES_NAMESPACE_ENV,
    KUBERNETES_POLL_INTERVAL_ENV,
    KUBERNETES_RUNTIME_CLASS_ENV,
    KUBERNETES_RUNTIME_HANDLER_ENV,
    KUBERNETES_STARTUP_TIMEOUT_ENV,
    SANDBOX_IMAGE_ENV,
    KubernetesJobOutcome,
    KubernetesJobTestExecutor,
    KubernetesSandboxConfiguration,
    KubernetesSandboxError,
    OfficialKubernetesSandboxAPI,
    kubernetes_sandbox_configuration_from_environment,
)
from aecontrol.sandbox import SandboxPolicy, _executor_from_environment

DIGEST_IMAGE = "registry.example/python@sha256:" + "a" * 64


class FakeAPI:
    def __init__(self, outcomes: list[KubernetesJobOutcome | None] | None = None) -> None:
        self.outcomes = list(outcomes or [KubernetesJobOutcome(True, "ok")])
        self.calls: list[tuple[str, str]] = []
        self.config_map: dict[str, object] | None = None
        self.network_policy: dict[str, object] | None = None
        self.job: dict[str, object] | None = None
        self.fail_on: str | None = None

    def verify_runtime_class(self, name: str, expected_handler: str) -> None:
        self.calls.append(("verify", f"{name}:{expected_handler}"))
        self._fail("verify")

    def create_config_map(self, namespace: str, body: dict[str, object]) -> None:
        self.calls.append(("create_config_map", namespace))
        self._fail("create_config_map")
        self.config_map = body

    def create_network_policy(self, namespace: str, body: dict[str, object]) -> None:
        self.calls.append(("create_network_policy", namespace))
        self._fail("create_network_policy")
        self.network_policy = body

    def create_job(self, namespace: str, body: dict[str, object]) -> None:
        self.calls.append(("create_job", namespace))
        self._fail("create_job")
        self.job = body

    def job_outcome(self, namespace: str, name: str) -> KubernetesJobOutcome | None:
        self.calls.append(("job_outcome", namespace))
        self._fail("job_outcome")
        return self.outcomes.pop(0) if self.outcomes else None

    def delete_job(self, namespace: str, name: str) -> None:
        self.calls.append(("delete_job", namespace))
        self._fail("delete_job")

    def delete_network_policy(self, namespace: str, name: str) -> None:
        self.calls.append(("delete_network_policy", namespace))
        self._fail("delete_network_policy")

    def delete_config_map(self, namespace: str, name: str) -> None:
        self.calls.append(("delete_config_map", namespace))
        self._fail("delete_config_map")

    def _fail(self, operation: str) -> None:
        if self.fail_on == operation:
            raise KubernetesSandboxError(f"failed {operation}")


def configuration(**overrides: object) -> KubernetesSandboxConfiguration:
    values: dict[str, object] = {
        "namespace": "aecontrol",
        "runtime_class": "kata-qemu",
        "runtime_handler": "kata-qemu",
        "image": DIGEST_IMAGE,
        "startup_timeout_seconds": 10,
        "poll_interval_seconds": 0.1,
    }
    values.update(overrides)
    return KubernetesSandboxConfiguration(**values)  # type: ignore[arg-type]


def workspace(tmp_path: Path) -> tuple[Path, Path]:
    app = tmp_path / "app.py"
    test = tmp_path / "_aecontrol_test.py"
    app.write_text("def solve():\n    return 42\n")
    test.write_text("from app import solve\nassert solve() == 42\n")
    return tmp_path, test


def test_executor_builds_one_hardened_runtimeclass_job_per_test(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, test_path = workspace(tmp_path)
    api = FakeAPI([None, KubernetesJobOutcome(True, "passed")])
    monkeypatch.setattr("aecontrol.kubernetes_sandbox.time.sleep", lambda _seconds: None)
    executor = KubernetesJobTestExecutor(configuration(), api)

    passed, output = executor.run_test(root, test_path, SandboxPolicy())

    assert passed
    assert output == "passed"
    assert api.calls[0] == ("verify", "kata-qemu:kata-qemu")
    assert [name for name, _ in api.calls[1:4]] == [
        "create_config_map",
        "create_network_policy",
        "create_job",
    ]
    assert [name for name, _ in api.calls[-3:]] == [
        "delete_job",
        "delete_network_policy",
        "delete_config_map",
    ]

    assert api.config_map is not None
    assert api.config_map["immutable"] is True
    assert api.config_map["data"] == {
        "app.py": "def solve():\n    return 42\n",
        "_aecontrol_test.py": "from app import solve\nassert solve() == 42\n",
    }
    assert api.network_policy is not None
    network_spec = api.network_policy["spec"]
    assert network_spec["policyTypes"] == ["Ingress", "Egress"]
    assert network_spec["ingress"] == []
    assert network_spec["egress"] == []

    assert api.job is not None
    job_spec = api.job["spec"]
    assert job_spec["backoffLimit"] == 0
    assert job_spec["activeDeadlineSeconds"] == 15
    pod = job_spec["template"]["spec"]
    assert pod["runtimeClassName"] == "kata-qemu"
    assert pod["automountServiceAccountToken"] is False
    assert pod["enableServiceLinks"] is False
    assert pod["hostNetwork"] is False
    assert pod["hostPID"] is False
    assert pod["hostIPC"] is False
    assert pod["securityContext"] == {
        "runAsNonRoot": True,
        "runAsUser": 65534,
        "runAsGroup": 65534,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    container = pod["containers"][0]
    assert container["image"] == DIGEST_IMAGE
    assert container["imagePullPolicy"] == "IfNotPresent"
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }
    assert container["resources"]["requests"] == container["resources"]["limits"]
    assert container["volumeMounts"][0]["readOnly"] is True


def test_candidate_failure_is_returned_and_output_is_bounded(tmp_path: Path) -> None:
    root, test_path = workspace(tmp_path)
    api = FakeAPI([KubernetesJobOutcome(False, "x" * 100)])
    executor = KubernetesJobTestExecutor(configuration(), api)

    passed, output = executor.run_test(root, test_path, SandboxPolicy(max_output_bytes=10))

    assert not passed
    assert output == "x" * 10 + "\n[output truncated]"
    assert [name for name, _ in api.calls[-3:]] == [
        "delete_job",
        "delete_network_policy",
        "delete_config_map",
    ]


@pytest.mark.parametrize(
    ("failure", "cleanup"),
    [
        ("create_config_map", ["delete_config_map"]),
        ("create_network_policy", ["delete_network_policy", "delete_config_map"]),
        ("create_job", ["delete_job", "delete_network_policy", "delete_config_map"]),
        ("job_outcome", ["delete_job", "delete_network_policy", "delete_config_map"]),
    ],
)
def test_partial_creation_failure_cleans_up_every_attempted_resource(
    failure: str, cleanup: list[str], tmp_path: Path
) -> None:
    root, test_path = workspace(tmp_path)
    api = FakeAPI()
    api.fail_on = failure
    executor = KubernetesJobTestExecutor(configuration(), api)

    with pytest.raises(KubernetesSandboxError, match=f"failed {failure}"):
        executor.run_test(root, test_path, SandboxPolicy())

    assert [name for name, _ in api.calls if name.startswith("delete_")] == cleanup


def test_cleanup_failure_fails_closed_after_candidate_completion(tmp_path: Path) -> None:
    root, test_path = workspace(tmp_path)
    api = FakeAPI()
    executor = KubernetesJobTestExecutor(configuration(), api)
    api.fail_on = "delete_job"

    with pytest.raises(KubernetesSandboxError, match="cleanup failed"):
        executor.run_test(root, test_path, SandboxPolicy())
    assert "delete_network_policy" in [name for name, _ in api.calls]
    assert "delete_config_map" in [name for name, _ in api.calls]


def test_bounded_completion_timeout_still_cleans_every_resource(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, test_path = workspace(tmp_path)
    api = FakeAPI([None])
    clock = iter([0.0, 20.0])
    monkeypatch.setattr("aecontrol.kubernetes_sandbox.time.monotonic", lambda: next(clock))
    executor = KubernetesJobTestExecutor(configuration(startup_timeout_seconds=1), api)

    with pytest.raises(KubernetesSandboxError, match="bounded completion deadline"):
        executor.run_test(root, test_path, SandboxPolicy(timeout_seconds=0.1))
    assert [name for name, _ in api.calls[-3:]] == [
        "delete_job",
        "delete_network_policy",
        "delete_config_map",
    ]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"namespace": "UPPER"}, "DNS label"),
        ({"runtime_class": "bad_class"}, "DNS subdomain"),
        ({"runtime_handler": "bad.handler"}, "DNS label"),
        ({"image": "python:3.12-slim"}, "pinned by SHA-256"),
        ({"startup_timeout_seconds": 0}, "between 1 and 300"),
        ({"startup_timeout_seconds": 301}, "between 1 and 300"),
        ({"poll_interval_seconds": 0}, "between 0.1 and 5"),
        ({"poll_interval_seconds": 6}, "between 0.1 and 5"),
    ],
)
def test_configuration_rejects_unsafe_values(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        configuration(**overrides)


def test_environment_configuration_uses_bounded_service_account_namespace(
    tmp_path: Path,
) -> None:
    namespace_file = tmp_path / "namespace"
    namespace_file.write_text("isolated-evals\n")
    environment = {
        KUBERNETES_RUNTIME_CLASS_ENV: "kata-qemu",
        KUBERNETES_RUNTIME_HANDLER_ENV: "kata-qemu",
        SANDBOX_IMAGE_ENV: DIGEST_IMAGE,
        KUBERNETES_STARTUP_TIMEOUT_ENV: "45",
        KUBERNETES_POLL_INTERVAL_ENV: "1",
    }

    loaded = kubernetes_sandbox_configuration_from_environment(environment, namespace_file)

    assert loaded == KubernetesSandboxConfiguration(
        namespace="isolated-evals",
        runtime_class="kata-qemu",
        runtime_handler="kata-qemu",
        image=DIGEST_IMAGE,
        startup_timeout_seconds=45,
        poll_interval_seconds=1,
    )

    namespace_file.write_text("x" * 254)
    with pytest.raises(ValueError, match=f"{KUBERNETES_NAMESPACE_ENV} is required"):
        kubernetes_sandbox_configuration_from_environment(environment, namespace_file)


def test_environment_configuration_requires_complete_numeric_values(tmp_path: Path) -> None:
    missing = {KUBERNETES_NAMESPACE_ENV: "aecontrol"}
    with pytest.raises(ValueError, match="must be set together"):
        kubernetes_sandbox_configuration_from_environment(missing, tmp_path / "absent")

    invalid = {
        KUBERNETES_NAMESPACE_ENV: "aecontrol",
        KUBERNETES_RUNTIME_CLASS_ENV: "kata-qemu",
        KUBERNETES_RUNTIME_HANDLER_ENV: "kata-qemu",
        SANDBOX_IMAGE_ENV: DIGEST_IMAGE,
        KUBERNETES_STARTUP_TIMEOUT_ENV: "slow",
    }
    with pytest.raises(ValueError, match="must be a number"):
        kubernetes_sandbox_configuration_from_environment(invalid)


def test_sandbox_backend_selector_builds_verified_kubernetes_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = FakeAPI()
    monkeypatch.setenv("AECONTROL_SANDBOX_BACKEND", "kubernetes-runtimeclass")
    monkeypatch.setenv(KUBERNETES_NAMESPACE_ENV, "aecontrol")
    monkeypatch.setenv(KUBERNETES_RUNTIME_CLASS_ENV, "kata-qemu")
    monkeypatch.setenv(KUBERNETES_RUNTIME_HANDLER_ENV, "kata-qemu")
    monkeypatch.setenv(SANDBOX_IMAGE_ENV, DIGEST_IMAGE)
    monkeypatch.setattr(
        OfficialKubernetesSandboxAPI,
        "from_in_cluster",
        classmethod(lambda _cls: api),
    )

    executor = _executor_from_environment()

    assert isinstance(executor, KubernetesJobTestExecutor)
    assert executor.name == "kubernetes-runtimeclass/kata-qemu"
    assert api.calls == [("verify", "kata-qemu:kata-qemu")]


class APIError(Exception):
    def __init__(self, status: int, detail: str = "sensitive response body") -> None:
        super().__init__(detail)
        self.status = status


def official_api() -> tuple[OfficialKubernetesSandboxAPI, Mock, Mock, Mock, Mock]:
    core = Mock()
    batch = Mock()
    networking = Mock()
    node = Mock()
    return (
        OfficialKubernetesSandboxAPI(core, batch, networking, node, APIError),
        core,
        batch,
        networking,
        node,
    )


def test_official_api_pins_runtimeclass_handler() -> None:
    api, _core, _batch, _networking, node = official_api()
    node.read_runtime_class.return_value = SimpleNamespace(handler="runc")

    with pytest.raises(KubernetesSandboxError, match="does not match"):
        api.verify_runtime_class("kata-qemu", "kata-qemu")

    node.read_runtime_class.return_value = SimpleNamespace(handler="kata-qemu")
    api.verify_runtime_class("kata-qemu", "kata-qemu")


def test_official_api_delegates_resource_creation() -> None:
    api, core, batch, networking, _node = official_api()
    body = {"metadata": {"name": "sandbox"}}

    api.create_config_map("aecontrol", body)
    api.create_network_policy("aecontrol", body)
    api.create_job("aecontrol", body)

    core.create_namespaced_config_map.assert_called_once_with("aecontrol", body)
    networking.create_namespaced_network_policy.assert_called_once_with("aecontrol", body)
    batch.create_namespaced_job.assert_called_once_with("aecontrol", body)


def test_official_api_reads_candidate_exit_and_logs() -> None:
    api, core, batch, _networking, _node = official_api()
    batch.read_namespaced_job_status.return_value = SimpleNamespace(
        status=SimpleNamespace(failed=0)
    )
    pod = SimpleNamespace(
        metadata=SimpleNamespace(name="sandbox-pod"),
        status=SimpleNamespace(
            phase="Succeeded",
            container_statuses=[
                SimpleNamespace(
                    state=SimpleNamespace(terminated=SimpleNamespace(exit_code=0), waiting=None)
                )
            ],
        ),
    )
    core.list_namespaced_pod.return_value = SimpleNamespace(items=[pod])
    core.read_namespaced_pod_log.return_value = "passed\n"

    assert api.job_outcome("aecontrol", "job") == KubernetesJobOutcome(True, "passed")


def test_official_api_classifies_deadline_and_image_failures() -> None:
    api, core, batch, _networking, _node = official_api()
    batch.read_namespaced_job_status.return_value = SimpleNamespace(
        status=SimpleNamespace(failed=1, conditions=[SimpleNamespace(reason="DeadlineExceeded")])
    )
    assert api.job_outcome("aecontrol", "job") == KubernetesJobOutcome(
        False, "microVM sandbox execution deadline exceeded"
    )

    batch.read_namespaced_job_status.return_value = SimpleNamespace(
        status=SimpleNamespace(failed=0)
    )
    pod = SimpleNamespace(
        metadata=SimpleNamespace(name="sandbox-pod"),
        status=SimpleNamespace(
            phase="Pending",
            container_statuses=[
                SimpleNamespace(
                    state=SimpleNamespace(
                        terminated=None, waiting=SimpleNamespace(reason="ImagePullBackOff")
                    )
                )
            ],
        ),
    )
    core.list_namespaced_pod.return_value = SimpleNamespace(items=[pod])
    with pytest.raises(KubernetesSandboxError, match="ImagePullBackOff"):
        api.job_outcome("aecontrol", "job")


def test_official_api_rejects_failed_jobs_and_invalid_container_status() -> None:
    api, core, batch, _networking, _node = official_api()
    batch.read_namespaced_job_status.return_value = SimpleNamespace(
        status=SimpleNamespace(failed=1, conditions=[])
    )
    core.list_namespaced_pod.return_value = SimpleNamespace(items=[])
    with pytest.raises(KubernetesSandboxError, match="failed before pod creation"):
        api.job_outcome("aecontrol", "job")

    batch.read_namespaced_job_status.return_value = SimpleNamespace(
        status=SimpleNamespace(failed=0)
    )
    pod = SimpleNamespace(
        metadata=SimpleNamespace(name="sandbox-pod"),
        status=SimpleNamespace(
            phase="Succeeded",
            container_statuses=[
                SimpleNamespace(
                    state=SimpleNamespace(
                        terminated=SimpleNamespace(exit_code="zero"), waiting=None
                    )
                )
            ],
        ),
    )
    core.list_namespaced_pod.return_value = SimpleNamespace(items=[pod])
    core.read_namespaced_pod_log.return_value = "output"
    with pytest.raises(KubernetesSandboxError, match="invalid container exit status"):
        api.job_outcome("aecontrol", "job")


def test_official_api_errors_are_sanitized_and_delete_404_is_idempotent() -> None:
    api, core, _batch, _networking, _node = official_api()
    core.create_namespaced_config_map.side_effect = APIError(403)

    with pytest.raises(KubernetesSandboxError, match="HTTP 403") as caught:
        api.create_config_map("aecontrol", {})
    assert "sensitive" not in str(caught.value)

    core.delete_namespaced_config_map.side_effect = APIError(404)
    api.delete_config_map("aecontrol", "missing")

    core.create_namespaced_config_map.side_effect = RuntimeError(
        "https://token@sensitive-api.example"
    )
    with pytest.raises(KubernetesSandboxError, match="request failed") as connection_error:
        api.create_config_map("aecontrol", {})
    assert "sensitive-api" not in str(connection_error.value)


def test_official_api_waits_for_foreground_job_deletion_before_policy_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, _core, batch, _networking, _node = official_api()
    batch.read_namespaced_job.side_effect = [SimpleNamespace(), APIError(404)]
    monkeypatch.setattr("aecontrol.kubernetes_sandbox.time.sleep", lambda _seconds: None)

    api.delete_job("aecontrol", "sandbox-job")

    batch.delete_namespaced_job.assert_called_once_with(
        "sandbox-job", "aecontrol", propagation_policy="Foreground"
    )
    assert batch.read_namespaced_job.call_count == 2


def test_official_api_job_deletion_timeout_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, _core, batch, _networking, _node = official_api()
    clock = iter([0.0, 20.0])
    monkeypatch.setattr("aecontrol.kubernetes_sandbox.time.monotonic", lambda: next(clock))

    with pytest.raises(KubernetesSandboxError, match="deletion did not complete"):
        api.delete_job("aecontrol", "sandbox-job")
    batch.delete_namespaced_job.assert_called_once()
