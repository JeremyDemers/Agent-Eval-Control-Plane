import tomllib
from pathlib import Path

import yaml

MANIFEST_ROOT = Path("deploy/kubernetes")


def _resources() -> list[dict[str, object]]:
    resources: list[dict[str, object]] = []
    for path in sorted(MANIFEST_ROOT.glob("*.yaml")):
        if path.name in {"kustomization.yaml", "secret.example.yaml"}:
            continue
        resources.extend(item for item in yaml.safe_load_all(path.read_text()) if item)
    return resources


def test_kubernetes_resources_have_unique_identities_and_matching_selectors() -> None:
    resources = _resources()
    identities = [(item["kind"], item["metadata"]["name"]) for item in resources]
    assert len(identities) == len(set(identities))
    deployments = [item for item in resources if item["kind"] in {"Deployment", "StatefulSet"}]
    for workload in deployments:
        spec = workload["spec"]
        labels = spec["template"]["metadata"]["labels"]
        assert spec["selector"]["matchLabels"].items() <= labels.items()


def test_kubernetes_workloads_enforce_operational_contracts() -> None:
    resources = _resources()
    by_name = {(item["kind"], item["metadata"]["name"]): item for item in resources}
    api = by_name[("Deployment", "api")]
    api_container = api["spec"]["template"]["spec"]["containers"][0]
    assert api_container["readinessProbe"]["httpGet"]["path"] == "/readyz"
    assert api_container["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert api["spec"]["replicas"] == 2

    for name in ("api", "cpu-worker", "gpu-worker"):
        pod_spec = by_name[("Deployment", name)]["spec"]["template"]["spec"]
        assert pod_spec["securityContext"]["runAsNonRoot"] is True
        assert pod_spec["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
        container = pod_spec["containers"][0]
        assert container["securityContext"]["allowPrivilegeEscalation"] is False
        assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    cpu = by_name[("Deployment", "cpu-worker")]["spec"]["template"]["spec"]["containers"][0]
    assert "runtime=nvidia-nim" in cpu["command"]

    gpu_spec = by_name[("Deployment", "gpu-worker")]["spec"]["template"]["spec"]
    gpu = gpu_spec["containers"][0]
    assert gpu_spec["nodeSelector"] == {"nvidia.com/gpu.present": "true"}
    assert gpu["resources"]["requests"]["nvidia.com/gpu"] == "1"
    assert gpu["resources"]["limits"]["nvidia.com/gpu"] == "1"
    assert "pool=kubernetes-gpu" in gpu["command"]

    for name in ("api", "cpu-worker", "gpu-worker"):
        container = by_name[("Deployment", name)]["spec"]["template"]["spec"]["containers"][0]
        env = {item["name"]: item["valueFrom"]["secretKeyRef"] for item in container["env"]}
        assert env["AECONTROL_ARTIFACT_SIGNING_KEY_ID"]["key"] == "artifact-signing-key-id"
        assert env["AECONTROL_ARTIFACT_SIGNING_KEYS"]["key"] == "artifact-signing-keys"


def test_kustomization_pins_release_image_and_secret_is_not_committed() -> None:
    kustomization = yaml.safe_load((MANIFEST_ROOT / "kustomization.yaml").read_text())
    project = tomllib.loads(Path("pyproject.toml").read_text())
    assert kustomization["images"] == [
        {
            "name": "ghcr.io/jeremydemers/agent-eval-control-plane",
            "newTag": project["project"]["version"],
        }
    ]
    assert "secret.example.yaml" not in kustomization["resources"]
    secret = yaml.safe_load((MANIFEST_ROOT / "secret.example.yaml").read_text())
    assert secret["stringData"]["password"] == "replace-me"
    assert secret["stringData"]["nvidia-api-key"] == "replace-me"
    assert secret["stringData"]["artifact-signing-key-id"] == "portfolio-2026-07"
    assert "portfolio-2026-07" in secret["stringData"]["artifact-signing-keys"]


def test_keda_overlay_scales_cpu_and_gpu_queues_independently() -> None:
    path = Path("deploy/overlays/keda/autoscaling.yaml")
    resources = list(yaml.safe_load_all(path.read_text()))
    hpa, cpu, gpu = resources
    assert hpa["kind"] == "HorizontalPodAutoscaler"
    assert hpa["spec"]["minReplicas"] == 2
    assert hpa["spec"]["maxReplicas"] == 8

    assert cpu["spec"]["scaleTargetRef"]["name"] == "cpu-worker"
    assert cpu["spec"]["minReplicaCount"] == 1
    assert cpu["spec"]["fallback"] == {"failureThreshold": 3, "replicas": 2}
    cpu_trigger = cpu["spec"]["triggers"][0]["metadata"]
    assert "required_accelerator = 'cpu'" in cpu_trigger["query"]
    assert cpu_trigger["targetQueryValue"] == "4"

    assert gpu["spec"]["scaleTargetRef"]["name"] == "gpu-worker"
    assert gpu["spec"]["minReplicaCount"] == 0
    assert gpu["spec"]["maxReplicaCount"] == 4
    gpu_trigger = gpu["spec"]["triggers"][0]["metadata"]
    assert "required_accelerator = 'cuda'" in gpu_trigger["query"]
    assert gpu_trigger["targetQueryValue"] == "1"
    for trigger in (cpu_trigger, gpu_trigger):
        assert trigger["connectionFromEnv"] == "DATABASE_URL"
        assert "status = 'queued'" in trigger["query"]
        assert "lease_expires_at < now()" in trigger["query"]


def test_mig_overlay_consumes_profile_resources_and_advertises_them() -> None:
    resources = list(yaml.safe_load_all(Path("deploy/overlays/mig/workers.yaml").read_text()))
    expected = {
        "mig-1g-10gb-worker": "1g.10gb",
        "mig-3g-40gb-worker": "3g.40gb",
    }

    for deployment in resources:
        name = deployment["metadata"]["name"]
        profile = expected[name]
        pod_spec = deployment["spec"]["template"]["spec"]
        assert pod_spec["nodeSelector"] == {"nvidia.com/mig.strategy": "mixed"}
        assert pod_spec["securityContext"]["runAsNonRoot"] is True
        assert pod_spec["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
        container = pod_spec["containers"][0]
        env = {item["name"]: item for item in container["env"]}
        assert env["AECONTROL_MIG_PROFILE"]["value"] == profile
        resource = f"nvidia.com/mig-{profile}"
        assert container["resources"]["requests"][resource] == "1"
        assert container["resources"]["limits"][resource] == "1"
        assert "pool=kubernetes-mig" in container["command"]
        assert "runtime=nvidia-nim" in container["command"]
        assert container["securityContext"]["allowPrivilegeEscalation"] is False
        assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]

    kustomization = yaml.safe_load(Path("deploy/overlays/mig/kustomization.yaml").read_text())
    project = tomllib.loads(Path("pyproject.toml").read_text())
    assert kustomization["resources"] == ["../../kubernetes", "workers.yaml"]
    assert kustomization["images"][0]["newTag"] == project["project"]["version"]
