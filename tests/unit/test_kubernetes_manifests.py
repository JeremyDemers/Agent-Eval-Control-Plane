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

    for name in ("api", "cpu-worker"):
        pod_spec = by_name[("Deployment", name)]["spec"]["template"]["spec"]
        assert pod_spec["securityContext"]["runAsNonRoot"] is True
        container = pod_spec["containers"][0]
        assert container["securityContext"]["allowPrivilegeEscalation"] is False
        assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]

    gpu_spec = by_name[("Deployment", "gpu-worker")]["spec"]["template"]["spec"]
    gpu = gpu_spec["containers"][0]
    assert gpu_spec["nodeSelector"] == {"nvidia.com/gpu.present": "true"}
    assert gpu["resources"]["requests"]["nvidia.com/gpu"] == "1"
    assert gpu["resources"]["limits"]["nvidia.com/gpu"] == "1"
    assert "pool=kubernetes-gpu" in gpu["command"]


def test_kustomization_pins_release_image_and_secret_is_not_committed() -> None:
    kustomization = yaml.safe_load((MANIFEST_ROOT / "kustomization.yaml").read_text())
    assert kustomization["images"] == [
        {
            "name": "ghcr.io/jeremydemers/agent-eval-control-plane",
            "newTag": "0.17.0",
        }
    ]
    assert "secret.example.yaml" not in kustomization["resources"]
    secret = yaml.safe_load((MANIFEST_ROOT / "secret.example.yaml").read_text())
    assert secret["stringData"]["password"] == "replace-me"
