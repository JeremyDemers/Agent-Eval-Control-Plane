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
    gpu_env = {item["name"]: item for item in gpu["env"]}
    assert gpu_env["AECONTROL_DCGM_EXPORTER_URL"]["value"].endswith(":9400/metrics")

    for name in ("api", "cpu-worker", "gpu-worker"):
        container = by_name[("Deployment", name)]["spec"]["template"]["spec"]["containers"][0]
        all_env = {item["name"]: item for item in container["env"]}
        assert all_env["AECONTROL_TENANT_ID"]["value"] == "default"
        env = {
            item["name"]: item["valueFrom"]["secretKeyRef"]
            for item in container["env"]
            if "valueFrom" in item
        }
        assert env["AECONTROL_ARTIFACT_SIGNING_KEY_ID"]["key"] == "artifact-signing-key-id"
        assert env["AECONTROL_ARTIFACT_SIGNING_ALGORITHM"]["key"] == "artifact-signing-algorithm"
        assert (
            env["AECONTROL_ARTIFACT_ED25519_PRIVATE_KEYS"]["key"] == "artifact-ed25519-private-keys"
        )
        assert (
            env["AECONTROL_ARTIFACT_ED25519_PUBLIC_KEYS"]["key"] == "artifact-ed25519-public-keys"
        )


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
    assert secret["stringData"]["artifact-signing-algorithm"] == "ed25519"
    assert "portfolio-2026-07" in secret["stringData"]["artifact-ed25519-private-keys"]
    assert "portfolio-2026-07" in secret["stringData"]["artifact-ed25519-public-keys"]


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
        assert "set_config('aecontrol.tenant_id', 'default', true)" in trigger["query"]
        assert "evaluation_jobs.tenant_id = tenant_context.tenant_id" in trigger["query"]
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
        assert env["AECONTROL_TENANT_ID"]["value"] == "default"
        assert env["AECONTROL_DCGM_EXPORTER_URL"]["value"].endswith(":9400/metrics")
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


def test_vault_transit_overlay_removes_private_keys_and_mounts_token_read_only() -> None:
    root = Path("deploy/overlays/vault-transit")
    patches = list(yaml.safe_load_all((root / "workloads.yaml").read_text()))
    assert {item["metadata"]["name"] for item in patches} == {
        "api",
        "cpu-worker",
        "gpu-worker",
    }
    for patch in patches:
        pod = patch["spec"]["template"]["spec"]
        assert pod["securityContext"]["fsGroup"] == 10001
        assert pod["volumes"][0]["secret"]["defaultMode"] == 0o440
        container = pod["containers"][0]
        env = {item["name"]: item for item in container["env"]}
        assert env["AECONTROL_ARTIFACT_ED25519_PRIVATE_KEYS"]["$patch"] == "delete"
        assert env["AECONTROL_ARTIFACT_VAULT_ADDR"]["value"].startswith("https://")
        assert env["AECONTROL_ARTIFACT_VAULT_TOKEN_FILE"]["value"].endswith("/token")
        assert env["AECONTROL_ARTIFACT_VAULT_KEY_VERSION"]["value"] == "1"
        assert container["volumeMounts"] == [
            {
                "name": "vault-token",
                "mountPath": "/var/run/secrets/aecontrol-vault",
                "readOnly": True,
            }
        ]
    kustomization = yaml.safe_load((root / "kustomization.yaml").read_text())
    project = tomllib.loads(Path("pyproject.toml").read_text())
    assert "token-secret.example.yaml" not in kustomization["resources"]
    assert kustomization["images"][0]["newTag"] == project["project"]["version"]


def test_cloudnative_pg_overlay_replaces_development_database_with_quorum_cluster() -> None:
    root = Path("deploy/overlays/cloudnative-pg")
    cluster = yaml.safe_load((root / "cluster.yaml").read_text())
    spec = cluster["spec"]

    assert cluster["apiVersion"] == "postgresql.cnpg.io/v1"
    assert cluster["kind"] == "Cluster"
    assert cluster["metadata"]["name"] == "aecontrol-postgres"
    assert spec["instances"] == 3
    assert spec["enableSuperuserAccess"] is False
    assert spec["imageName"].endswith(":17-standard-trixie")
    assert spec["primaryUpdateStrategy"] == "unsupervised"
    assert spec["primaryUpdateMethod"] == "switchover"
    assert spec["bootstrap"]["initdb"] == {
        "database": "aecontrol",
        "owner": "aecontrol",
        "dataChecksums": True,
        "encoding": "UTF8",
    }
    synchronous = spec["postgresql"]["synchronous"]
    assert synchronous == {
        "method": "any",
        "number": 1,
        "dataDurability": "required",
        "failoverQuorum": True,
    }
    assert spec["affinity"] == {
        "enablePodAntiAffinity": True,
        "topologyKey": "kubernetes.io/hostname",
        "podAntiAffinityType": "required",
    }
    assert spec["storage"]["size"] == "20Gi"
    assert spec["walStorage"]["size"] == "5Gi"

    kustomization = yaml.safe_load((root / "kustomization.yaml").read_text())
    project = tomllib.loads(Path("pyproject.toml").read_text())
    assert kustomization["resources"] == ["../../kubernetes", "cluster.yaml"]
    assert kustomization["images"][0]["newTag"] == project["project"]["version"]
    patches = kustomization["patches"]
    deleted = {(item["target"]["kind"], item["target"].get("name")) for item in patches[:2]}
    assert deleted == {("StatefulSet", "postgres"), ("Service", "postgres")}
    database_patch = patches[2]
    assert database_patch["target"]["kind"] == "Deployment"
    assert "aecontrol-postgres-app" in database_patch["patch"]
    assert "value: uri" in database_patch["patch"]


def test_cloudnative_pg_monitoring_is_explicitly_opt_in() -> None:
    root = Path("deploy/overlays/cloudnative-pg-monitoring")
    kustomization = yaml.safe_load((root / "kustomization.yaml").read_text())
    monitor = yaml.safe_load((root / "podmonitor.yaml").read_text())

    assert kustomization["resources"] == ["../cloudnative-pg", "podmonitor.yaml"]
    assert monitor["kind"] == "PodMonitor"
    assert monitor["spec"]["selector"]["matchLabels"] == {"cnpg.io/cluster": "aecontrol-postgres"}
    endpoint = monitor["spec"]["podMetricsEndpoints"][0]
    assert endpoint == {"port": "metrics", "interval": "30s", "scrapeTimeout": "10s"}


def test_cloudnative_pg_pitr_uses_plugin_backups_and_bounded_retention() -> None:
    root = Path("deploy/overlays/cloudnative-pg-pitr")
    kustomization = yaml.safe_load((root / "kustomization.yaml").read_text())
    project = tomllib.loads(Path("pyproject.toml").read_text())
    assert kustomization["resources"] == [
        "../cloudnative-pg",
        "object-store.yaml",
        "scheduled-backup.yaml",
    ]
    assert kustomization["images"][0]["newTag"] == project["project"]["version"]
    plugin_patch = yaml.safe_load(kustomization["patches"][0]["patch"])
    assert plugin_patch == [
        {
            "op": "add",
            "path": "/spec/plugins",
            "value": [
                {
                    "name": "barman-cloud.cloudnative-pg.io",
                    "isWALArchiver": True,
                    "parameters": {"barmanObjectName": "aecontrol-postgres-backup"},
                }
            ],
        }
    ]

    object_store = yaml.safe_load((root / "object-store.yaml").read_text())
    assert object_store["apiVersion"] == "barmancloud.cnpg.io/v1"
    assert object_store["kind"] == "ObjectStore"
    assert object_store["metadata"]["name"] == "aecontrol-postgres-backup"
    spec = object_store["spec"]
    assert spec["retentionPolicy"] == "30d"
    assert spec["configuration"]["destinationPath"].startswith("s3://replace-with-")
    assert spec["configuration"]["wal"] == {
        "compression": "gzip",
        "encryption": "AES256",
        "maxParallel": 8,
    }
    assert spec["configuration"]["data"] == {
        "compression": "gzip",
        "encryption": "AES256",
    }
    credentials = spec["configuration"]["s3Credentials"]
    assert {item["name"] for item in credentials.values()} == {"aecontrol-backup-s3"}
    assert spec["instanceSidecarConfiguration"]["retentionPolicyIntervalSeconds"] == 1800

    scheduled = yaml.safe_load((root / "scheduled-backup.yaml").read_text())
    assert scheduled["kind"] == "ScheduledBackup"
    assert scheduled["spec"] == {
        "schedule": "0 0 2 * * *",
        "immediate": True,
        "suspend": False,
        "backupOwnerReference": "self",
        "target": "prefer-standby",
        "cluster": {"name": "aecontrol-postgres"},
        "method": "plugin",
        "pluginConfiguration": {"name": "barman-cloud.cloudnative-pg.io"},
    }
    assert "backup-secret.example.yaml" not in kustomization["resources"]
    assert "restore.example.yaml" not in kustomization["resources"]


def test_cloudnative_pg_restore_template_is_isolated_and_time_targeted() -> None:
    restore = yaml.safe_load(
        Path("deploy/overlays/cloudnative-pg-pitr/restore.example.yaml").read_text()
    )
    spec = restore["spec"]
    assert restore["metadata"]["name"] == "aecontrol-postgres-restore"
    assert spec["instances"] == 3
    recovery = spec["bootstrap"]["recovery"]
    assert recovery["source"] == "aecontrol-postgres-source"
    assert recovery["recoveryTarget"]["targetTime"] == "REPLACE_WITH_RFC3339_TIMESTAMP"
    external = spec["externalClusters"][0]
    assert external["name"] == recovery["source"]
    assert external["plugin"]["parameters"] == {
        "barmanObjectName": "aecontrol-postgres-backup",
        "serverName": "aecontrol-postgres",
    }
    assert "plugins" not in spec
    assert spec["storage"]["size"] == "20Gi"
    assert spec["walStorage"]["size"] == "5Gi"


def test_recovery_verification_job_is_read_only_bounded_and_uses_public_keys() -> None:
    job = yaml.safe_load(
        Path(
            "deploy/overlays/cloudnative-pg-pitr/recovery-verification-job.example.yaml"
        ).read_text()
    )
    project = tomllib.loads(Path("pyproject.toml").read_text())
    spec = job["spec"]
    pod = spec["template"]["spec"]
    container = pod["containers"][0]
    assert job["kind"] == "Job"
    assert spec["backoffLimit"] == 0
    assert spec["activeDeadlineSeconds"] == 1800
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert container["image"].endswith(f":{project['project']['version']}")
    assert container["command"] == ["/app/.venv/bin/aecontrol"]
    assert container["args"][:3] == ["store", "verify-recovery", "--checkpoint"]
    assert "--json" in container["args"]
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
    }
    environment = {item["name"]: item["valueFrom"] for item in container["env"]}
    assert environment["DATABASE_URL"]["secretKeyRef"] == {
        "name": "aecontrol-postgres-restore-app",
        "key": "uri",
    }
    assert environment["AECONTROL_ARTIFACT_ED25519_PUBLIC_KEYS"]["secretKeyRef"]["name"] == (
        "aecontrol-recovery-verifier"
    )
    assert "AECONTROL_ARTIFACT_ED25519_PRIVATE_KEYS" not in environment
    assert "AECONTROL_ARTIFACT_VAULT_TOKEN" not in environment


def test_scheduled_recovery_drill_has_least_privilege_rbac_and_bounded_lifecycle() -> None:
    root = Path("deploy/overlays/cloudnative-pg-recovery-drill")
    project = tomllib.loads(Path("pyproject.toml").read_text())
    kustomization = yaml.safe_load((root / "kustomization.yaml").read_text())
    assert kustomization["resources"] == [
        "../cloudnative-pg-pitr",
        "service-account.yaml",
        "role.yaml",
        "role-binding.yaml",
        "cronjob.yaml",
    ]
    assert kustomization["images"][0]["newTag"] == project["project"]["version"]

    role = yaml.safe_load((root / "role.yaml").read_text())
    assert role["rules"] == [
        {
            "apiGroups": ["postgresql.cnpg.io"],
            "resources": ["clusters"],
            "verbs": ["create", "get", "list", "delete"],
        },
        {
            "apiGroups": ["batch"],
            "resources": ["jobs"],
            "verbs": ["create", "get", "list", "delete"],
        },
    ]
    binding = yaml.safe_load((root / "role-binding.yaml").read_text())
    assert binding["roleRef"]["kind"] == "Role"
    assert binding["subjects"] == [{"kind": "ServiceAccount", "name": "aecontrol-recovery-drill"}]

    cronjob = yaml.safe_load((root / "cronjob.yaml").read_text())
    spec = cronjob["spec"]
    assert spec["schedule"] == "0 4 * * 0"
    assert spec["timeZone"] == "Etc/UTC"
    assert spec["concurrencyPolicy"] == "Forbid"
    assert spec["startingDeadlineSeconds"] == 3600
    assert spec["successfulJobsHistoryLimit"] == 3
    assert spec["failedJobsHistoryLimit"] == 3
    assert spec["jobTemplate"]["spec"]["backoffLimit"] == 0
    assert spec["jobTemplate"]["spec"]["activeDeadlineSeconds"] == 10800
    pod = spec["jobTemplate"]["spec"]["template"]["spec"]
    assert pod["serviceAccountName"] == "aecontrol-recovery-drill"
    assert pod["securityContext"]["runAsNonRoot"] is True
    container = pod["containers"][0]
    assert container["image"].endswith(f":{project['project']['version']}")
    assert container["command"] == ["/app/.venv/bin/aecontrol"]
    assert container["args"] == ["recovery-drill", "--json"]
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
    }
    environment = {item["name"]: item["value"] for item in container["env"]}
    assert environment["AECONTROL_RECOVERY_DRILL_VERIFIER_IMAGE"].endswith(
        f":{project['project']['version']}"
    )
    assert "AECONTROL_RECOVERY_DRILL_CHECKPOINT_SECRET" in environment
    assert "AECONTROL_RECOVERY_DRILL_REPORT_SECRET" in environment

    assert "checkpoint-secret.example.yaml" not in kustomization["resources"]
    assert "verifier-secret.example.yaml" not in kustomization["resources"]
    assert "report-secret.example.yaml" not in kustomization["resources"]


def test_cloudnative_pg_pitr_monitoring_alerts_on_failed_and_stale_backups() -> None:
    root = Path("deploy/overlays/cloudnative-pg-pitr-monitoring")
    kustomization = yaml.safe_load((root / "kustomization.yaml").read_text())
    assert kustomization["resources"] == [
        "../cloudnative-pg-pitr",
        "podmonitor.yaml",
        "prometheus-rules.yaml",
    ]
    rules = yaml.safe_load((root / "prometheus-rules.yaml").read_text())
    alerts = {item["alert"]: item for item in rules["spec"]["groups"][0]["rules"]}
    assert set(alerts) == {"AgentEvalPostgresBackupFailed", "AgentEvalPostgresBackupStale"}
    for alert in alerts.values():
        assert "barman_cloud_cloudnative_pg_io" in alert["expr"]
        assert alert["labels"]["severity"] == "critical"
    assert alerts["AgentEvalPostgresBackupFailed"]["for"] == "15m"
    assert alerts["AgentEvalPostgresBackupStale"]["for"] == "1h"
    assert "absent(" in alerts["AgentEvalPostgresBackupStale"]["expr"]
