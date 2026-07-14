from __future__ import annotations

import math
import os
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from aecontrol.sandbox import SHA256_IMAGE_PATTERN, SandboxPolicy

KUBERNETES_NAMESPACE_ENV = "AECONTROL_SANDBOX_KUBERNETES_NAMESPACE"
KUBERNETES_RUNTIME_CLASS_ENV = "AECONTROL_SANDBOX_KUBERNETES_RUNTIME_CLASS"
KUBERNETES_RUNTIME_HANDLER_ENV = "AECONTROL_SANDBOX_KUBERNETES_RUNTIME_HANDLER"
KUBERNETES_STARTUP_TIMEOUT_ENV = "AECONTROL_SANDBOX_KUBERNETES_STARTUP_TIMEOUT_SECONDS"
KUBERNETES_POLL_INTERVAL_ENV = "AECONTROL_SANDBOX_KUBERNETES_POLL_INTERVAL_SECONDS"
SANDBOX_IMAGE_ENV = "AECONTROL_SANDBOX_IMAGE"
SERVICE_ACCOUNT_NAMESPACE_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
_DNS_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_DNS_SUBDOMAIN_PATTERN = re.compile(r"^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$")


class KubernetesSandboxError(RuntimeError):
    """The cluster could not execute a candidate in the required isolated runtime."""


@dataclass(frozen=True)
class KubernetesSandboxConfiguration:
    namespace: str
    runtime_class: str
    runtime_handler: str
    image: str
    startup_timeout_seconds: float = 30
    poll_interval_seconds: float = 0.5

    def __post_init__(self) -> None:
        if not _DNS_LABEL_PATTERN.fullmatch(self.namespace):
            raise ValueError(f"{KUBERNETES_NAMESPACE_ENV} must be a DNS label")
        if not _DNS_SUBDOMAIN_PATTERN.fullmatch(self.runtime_class):
            raise ValueError(f"{KUBERNETES_RUNTIME_CLASS_ENV} must be a DNS subdomain")
        if not _DNS_LABEL_PATTERN.fullmatch(self.runtime_handler):
            raise ValueError(f"{KUBERNETES_RUNTIME_HANDLER_ENV} must be a DNS label")
        if SHA256_IMAGE_PATTERN.fullmatch(self.image) is None:
            raise ValueError(f"{SANDBOX_IMAGE_ENV} must be pinned by SHA-256 digest")
        if not 1 <= self.startup_timeout_seconds <= 300:
            raise ValueError(f"{KUBERNETES_STARTUP_TIMEOUT_ENV} must be between 1 and 300 seconds")
        if not 0.1 <= self.poll_interval_seconds <= 5:
            raise ValueError(f"{KUBERNETES_POLL_INTERVAL_ENV} must be between 0.1 and 5 seconds")


@dataclass(frozen=True)
class KubernetesJobOutcome:
    passed: bool
    output: str


class KubernetesSandboxAPI(Protocol):
    def verify_runtime_class(self, name: str, expected_handler: str) -> None: ...

    def create_config_map(self, namespace: str, body: dict[str, object]) -> None: ...

    def create_network_policy(self, namespace: str, body: dict[str, object]) -> None: ...

    def create_job(self, namespace: str, body: dict[str, object]) -> None: ...

    def job_outcome(self, namespace: str, name: str) -> KubernetesJobOutcome | None: ...

    def delete_job(self, namespace: str, name: str) -> None: ...

    def delete_network_policy(self, namespace: str, name: str) -> None: ...

    def delete_config_map(self, namespace: str, name: str) -> None: ...


class OfficialKubernetesSandboxAPI:
    def __init__(
        self, core: Any, batch: Any, networking: Any, node: Any, api_error: type[Exception]
    ):
        self.core = core
        self.batch = batch
        self.networking = networking
        self.node = node
        self.api_error = api_error

    @classmethod
    def from_in_cluster(cls) -> OfficialKubernetesSandboxAPI:
        try:
            from kubernetes import client, config  # type: ignore[import-untyped]
            from kubernetes.client.exceptions import ApiException  # type: ignore[import-untyped]
        except ImportError as error:
            raise RuntimeError("Kubernetes runtime dependency is unavailable") from error
        try:
            config.load_incluster_config()
        except Exception as error:
            raise KubernetesSandboxError("Kubernetes in-cluster configuration failed") from error
        return cls(
            client.CoreV1Api(),
            client.BatchV1Api(),
            client.NetworkingV1Api(),
            client.NodeV1Api(),
            ApiException,
        )

    def verify_runtime_class(self, name: str, expected_handler: str) -> None:
        runtime_class = self._call("read RuntimeClass", self.node.read_runtime_class, name)
        if getattr(runtime_class, "handler", None) != expected_handler:
            raise KubernetesSandboxError(
                "Kubernetes RuntimeClass handler does not match the pinned handler"
            )

    def create_config_map(self, namespace: str, body: dict[str, object]) -> None:
        self._call(
            "create sandbox ConfigMap", self.core.create_namespaced_config_map, namespace, body
        )

    def create_network_policy(self, namespace: str, body: dict[str, object]) -> None:
        self._call(
            "create sandbox NetworkPolicy",
            self.networking.create_namespaced_network_policy,
            namespace,
            body,
        )

    def create_job(self, namespace: str, body: dict[str, object]) -> None:
        self._call("create sandbox Job", self.batch.create_namespaced_job, namespace, body)

    def job_outcome(self, namespace: str, name: str) -> KubernetesJobOutcome | None:
        job = self._call("read sandbox Job", self.batch.read_namespaced_job_status, name, namespace)
        status = getattr(job, "status", None)
        job_failed = getattr(status, "failed", None) if status is not None else None
        if job_failed:
            conditions = getattr(status, "conditions", None) or []
            if any(
                getattr(condition, "reason", None) == "DeadlineExceeded" for condition in conditions
            ):
                return KubernetesJobOutcome(False, "microVM sandbox execution deadline exceeded")
        pod = self._sandbox_pod(namespace, name)
        if pod is None:
            if job_failed:
                raise KubernetesSandboxError("Kubernetes sandbox Job failed before pod creation")
            return None
        pod_status = getattr(pod, "status", None)
        container_statuses = getattr(pod_status, "container_statuses", None) or []
        if container_statuses:
            state = getattr(container_statuses[0], "state", None)
            terminated = getattr(state, "terminated", None)
            if terminated is not None:
                output = self._pod_log(namespace, getattr(pod.metadata, "name", ""))
                exit_code = getattr(terminated, "exit_code", None)
                if not isinstance(exit_code, int):
                    raise KubernetesSandboxError(
                        "Kubernetes sandbox returned an invalid container exit status"
                    )
                return KubernetesJobOutcome(exit_code == 0, output or "ok")
            waiting = getattr(state, "waiting", None)
            reason = getattr(waiting, "reason", None)
            if reason in {
                "CreateContainerConfigError",
                "ErrImageNeverPull",
                "ErrImagePull",
                "ImagePullBackOff",
                "InvalidImageName",
                "RunContainerError",
            }:
                raise KubernetesSandboxError(f"Kubernetes sandbox pod could not start: {reason}")
        if getattr(pod_status, "phase", None) == "Failed":
            raise KubernetesSandboxError(
                "Kubernetes sandbox pod failed before candidate completion"
            )
        return None

    def delete_job(self, namespace: str, name: str) -> None:
        try:
            self.batch.delete_namespaced_job(name, namespace, propagation_policy="Foreground")
        except self.api_error as error:
            if getattr(error, "status", None) == 404:
                return
            raise KubernetesSandboxError(
                f"delete sandbox Job failed with HTTP {getattr(error, 'status', 'unknown')}"
            ) from error
        except Exception as error:
            raise KubernetesSandboxError("delete sandbox Job request failed") from error
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                self.batch.read_namespaced_job(name, namespace)
            except self.api_error as error:
                if getattr(error, "status", None) == 404:
                    return
                raise KubernetesSandboxError(
                    "verify sandbox Job deletion failed with HTTP "
                    f"{getattr(error, 'status', 'unknown')}"
                ) from error
            except Exception as error:
                raise KubernetesSandboxError(
                    "verify sandbox Job deletion request failed"
                ) from error
            time.sleep(0.1)
        raise KubernetesSandboxError("Kubernetes sandbox Job deletion did not complete")

    def delete_network_policy(self, namespace: str, name: str) -> None:
        self._delete(
            "delete sandbox NetworkPolicy",
            self.networking.delete_namespaced_network_policy,
            name,
            namespace,
        )

    def delete_config_map(self, namespace: str, name: str) -> None:
        self._delete(
            "delete sandbox ConfigMap", self.core.delete_namespaced_config_map, name, namespace
        )

    def _sandbox_pod(self, namespace: str, job_name: str) -> Any | None:
        pods = self._call(
            "list sandbox pods",
            self.core.list_namespaced_pod,
            namespace,
            label_selector=f"job-name={job_name}",
        )
        items = getattr(pods, "items", None) or []
        return items[0] if items else None

    def _pod_log(self, namespace: str, pod_name: str) -> str:
        value = self._call(
            "read sandbox pod log",
            self.core.read_namespaced_pod_log,
            pod_name,
            namespace,
            timestamps=False,
            _request_timeout=10,
        )
        if not isinstance(value, str):
            raise KubernetesSandboxError("Kubernetes sandbox returned an invalid pod log")
        return value.strip()

    def _delete(self, operation: str, function: Any, *args: object, **kwargs: object) -> None:
        try:
            function(*args, **kwargs)
        except self.api_error as error:
            if getattr(error, "status", None) != 404:
                raise KubernetesSandboxError(
                    f"{operation} failed with HTTP {getattr(error, 'status', 'unknown')}"
                ) from error
        except Exception as error:
            raise KubernetesSandboxError(f"{operation} request failed") from error

    def _call(self, operation: str, function: Any, *args: object, **kwargs: object) -> Any:
        try:
            return function(*args, **kwargs)
        except self.api_error as error:
            raise KubernetesSandboxError(
                f"{operation} failed with HTTP {getattr(error, 'status', 'unknown')}"
            ) from error
        except Exception as error:
            raise KubernetesSandboxError(f"{operation} request failed") from error


class KubernetesJobTestExecutor:
    def __init__(
        self,
        configuration: KubernetesSandboxConfiguration,
        api: KubernetesSandboxAPI | None = None,
    ) -> None:
        self.configuration = configuration
        self.api = api or OfficialKubernetesSandboxAPI.from_in_cluster()
        self.api.verify_runtime_class(configuration.runtime_class, configuration.runtime_handler)
        self.name = f"kubernetes-runtimeclass/{configuration.runtime_class}"

    def run_test(self, root: Path, test_path: Path, policy: SandboxPolicy) -> tuple[bool, str]:
        run_id = uuid4().hex
        name = f"aecontrol-{run_id}"
        labels = {
            "app.kubernetes.io/name": "aecontrol-sandbox",
            "aecontrol.dev/run-id": run_id,
        }
        config_map = self._config_map(name, labels, root, test_path)
        network_policy = self._network_policy(name, labels)
        job = self._job(name, labels, test_path.name, policy)
        attempted: list[str] = []
        try:
            attempted.append("config_map")
            self.api.create_config_map(self.configuration.namespace, config_map)
            attempted.append("network_policy")
            self.api.create_network_policy(self.configuration.namespace, network_policy)
            attempted.append("job")
            self.api.create_job(self.configuration.namespace, job)
            deadline = (
                time.monotonic()
                + policy.timeout_seconds
                + self.configuration.startup_timeout_seconds
            )
            while time.monotonic() < deadline:
                outcome = self.api.job_outcome(self.configuration.namespace, name)
                if outcome is not None:
                    return outcome.passed, _truncate(outcome.output, policy.max_output_bytes)
                time.sleep(self.configuration.poll_interval_seconds)
            raise KubernetesSandboxError(
                "Kubernetes sandbox exceeded its bounded completion deadline"
            )
        finally:
            self._cleanup(name, attempted)

    def _config_map(
        self, name: str, labels: dict[str, str], root: Path, test_path: Path
    ) -> dict[str, object]:
        return {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": name, "labels": labels},
            "immutable": True,
            "data": {
                "app.py": (root / "app.py").read_text(),
                test_path.name: test_path.read_text(),
            },
        }

    @staticmethod
    def _network_policy(name: str, labels: dict[str, str]) -> dict[str, object]:
        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": name, "labels": labels},
            "spec": {
                "podSelector": {
                    "matchLabels": {"aecontrol.dev/run-id": labels["aecontrol.dev/run-id"]}
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [],
            },
        }

    def _job(
        self, name: str, labels: dict[str, str], test_name: str, policy: SandboxPolicy
    ) -> dict[str, object]:
        active_deadline = math.ceil(
            policy.timeout_seconds + self.configuration.startup_timeout_seconds
        )
        resources = {
            "cpu": "500m",
            "memory": str(policy.memory_bytes),
            "ephemeral-storage": str(policy.max_file_bytes),
        }
        return {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {"name": name, "labels": labels},
            "spec": {
                "backoffLimit": 0,
                "activeDeadlineSeconds": active_deadline,
                "ttlSecondsAfterFinished": 300,
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "runtimeClassName": self.configuration.runtime_class,
                        "automountServiceAccountToken": False,
                        "enableServiceLinks": False,
                        "restartPolicy": "Never",
                        "terminationGracePeriodSeconds": 1,
                        "hostNetwork": False,
                        "hostPID": False,
                        "hostIPC": False,
                        "shareProcessNamespace": False,
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 65534,
                            "runAsGroup": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"},
                        },
                        "containers": [
                            {
                                "name": "candidate",
                                "image": self.configuration.image,
                                "imagePullPolicy": "IfNotPresent",
                                "command": ["python", "-B", f"/workspace/{test_name}"],
                                "env": [
                                    {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                                    {"name": "PYTHONPATH", "value": "/workspace"},
                                ],
                                "resources": {"requests": resources, "limits": resources},
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]},
                                },
                                "volumeMounts": [
                                    {
                                        "name": "workspace",
                                        "mountPath": "/workspace",
                                        "readOnly": True,
                                    }
                                ],
                            }
                        ],
                        "volumes": [
                            {
                                "name": "workspace",
                                "configMap": {"name": name, "defaultMode": 0o444},
                            }
                        ],
                    },
                },
            },
        }

    def _cleanup(self, name: str, attempted: list[str]) -> None:
        errors: list[KubernetesSandboxError] = []
        operations = (
            ("job", self.api.delete_job),
            ("network_policy", self.api.delete_network_policy),
            ("config_map", self.api.delete_config_map),
        )
        for resource, delete in operations:
            if resource not in attempted:
                continue
            try:
                delete(self.configuration.namespace, name)
            except KubernetesSandboxError as error:
                errors.append(error)
        if errors:
            raise KubernetesSandboxError("Kubernetes sandbox cleanup failed") from errors[0]


def kubernetes_sandbox_configuration_from_environment(
    environment: Mapping[str, str] | None = None,
    namespace_path: Path = SERVICE_ACCOUNT_NAMESPACE_PATH,
) -> KubernetesSandboxConfiguration:
    env = environment if environment is not None else os.environ
    namespace = env.get(KUBERNETES_NAMESPACE_ENV, "").strip()
    if not namespace:
        try:
            if not namespace_path.is_file() or namespace_path.stat().st_size > 253:
                raise ValueError(f"{KUBERNETES_NAMESPACE_ENV} is required")
            namespace = namespace_path.read_text().strip()
        except OSError as error:
            raise ValueError(f"{KUBERNETES_NAMESPACE_ENV} is required") from error
    runtime_class = env.get(KUBERNETES_RUNTIME_CLASS_ENV, "").strip()
    runtime_handler = env.get(KUBERNETES_RUNTIME_HANDLER_ENV, "").strip()
    image = env.get(SANDBOX_IMAGE_ENV, "").strip()
    if not runtime_class or not runtime_handler or not image:
        raise ValueError(
            f"{KUBERNETES_RUNTIME_CLASS_ENV}, {KUBERNETES_RUNTIME_HANDLER_ENV}, and "
            f"{SANDBOX_IMAGE_ENV} must be set together"
        )
    return KubernetesSandboxConfiguration(
        namespace=namespace,
        runtime_class=runtime_class,
        runtime_handler=runtime_handler,
        image=image,
        startup_timeout_seconds=_environment_float(
            env.get(KUBERNETES_STARTUP_TIMEOUT_ENV, "30"), KUBERNETES_STARTUP_TIMEOUT_ENV
        ),
        poll_interval_seconds=_environment_float(
            env.get(KUBERNETES_POLL_INTERVAL_ENV, "0.5"), KUBERNETES_POLL_INTERVAL_ENV
        ),
    )


def _environment_float(value: str, name: str) -> float:
    try:
        return float(value)
    except ValueError as error:
        raise ValueError(f"{name} must be a number") from error


def _truncate(value: str, maximum_bytes: int) -> str:
    encoded = value.encode()
    if len(encoded) <= maximum_bytes:
        return value
    return encoded[:maximum_bytes].decode(errors="replace") + "\n[output truncated]"
